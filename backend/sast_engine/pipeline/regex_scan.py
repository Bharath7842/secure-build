"""regex_scan.py — deterministic, LLM-free regex pass over risk-tiered files.

Applies the curated pattern set in the `rules/` directory (split per language;
each rule is id/title/description/cwe/severity/category/owasp/languages/
frameworks/requires_dependency/pattern) against the on-disk content of files
the module/risk map (`node_map_modules_and_risk`) flagged at a given risk
tier. This is what gates the MEDIUM/LOW triage pass: a file with no hit here
never reaches the LLM at all.

Rules are filtered per file/project by RegexRule.applies_to, on three
independent axes — `languages` (a Java rule never runs against a .ts file),
`frameworks` (a JAX-RS rule only fires when JAX-RS was actually detected), and
`requires_dependency` (a gadget-chain rule only fires when the vulnerable
library is really declared). Every axis is empty-means-universal, so the same
catalog adapts to whatever stack the repo turns out to be.

`surfaces.json` maps detected stack signals to named vulnerability surfaces
and the rules that cover them, reproducing the legacy audit docs' "Tech Stack
Detected -> Known Vulnerability Surface -> Targeted Regex" reasoning for any
repo. Surfaces narrate and prioritise; they never gate.

No LLM call anywhere in this module; every hit is a plain `re.search` against
one source line, or a capped `re.finditer` over the whole file for multiline
rules.
"""

from __future__ import annotations

import json
import multiprocessing
import os
import re
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Sequence, Set, Tuple

_MAX_SNIPPET_LEN = 160
# Multiline rules search the whole file with finditer; past this many hits
# per (file, rule) the rest are the same construct repeated.
MULTILINE_HITS_PER_FILE_CAP = 25

# Files in a rules directory that hold something other than a rule array.
SURFACES_FILENAME = "surfaces.json"


# ===========================================================================
# Dependency conditions
# ===========================================================================
#
# Some patterns are only worth reporting when a specific vulnerable library is
# actually on the classpath — `implements Serializable` matters because a
# gadget-chain commons-collections is present, not on its own. A rule may name
# `requires_dependency` to say so; rules without one are unconditional.

_VERSION_NUM_RE = re.compile(r"\d+")


def parse_version(raw: Optional[str]) -> Optional[tuple]:
    """`"6.0.0.Final"` -> `(6, 0, 0)`. Returns None when nothing parses.

    Deliberately lenient: Maven/npm versions carry qualifiers (`.Final`,
    `-RELEASE`, `^1.2.3`) and unresolved `${property}` placeholders. We compare
    the leading numeric components and ignore the rest, which is enough to tell
    `3.2` from `3.2.2`.
    """
    if not raw:
        return None
    numbers = _VERSION_NUM_RE.findall(str(raw))
    if not numbers:
        return None
    return tuple(int(n) for n in numbers[:4])


def _version_satisfies(actual: Optional[str], *, lt: Optional[str], lte: Optional[str]) -> bool:
    """True when `actual` is below the given bound.

    Fail-open: an absent or unparseable version returns True. A missing
    version must never be what silently disables a security rule — we would
    rather show a finding against an unknown version than hide a real one.
    """
    if lt is None and lte is None:
        return True
    actual_v = parse_version(actual)
    if actual_v is None:
        return True
    if lt is not None:
        bound = parse_version(lt)
        if bound is not None and actual_v >= bound:
            return False
    if lte is not None:
        bound = parse_version(lte)
        if bound is not None and actual_v > bound:
            return False
    return True


class DependencyCondition:
    """One `requires_dependency` entry: a name plus an optional version bound."""

    __slots__ = ("name", "version_lt", "version_lte")

    def __init__(self, raw: Dict[str, Any]):
        self.name = str(raw["name"]).strip().lower()
        self.version_lt = raw.get("version_lt")
        self.version_lte = raw.get("version_lte")

    def matches(self, dependency_index: Dict[str, List[Optional[str]]]) -> bool:
        versions = dependency_index.get(self.name)
        if versions is None:
            return False
        return any(
            _version_satisfies(v, lt=self.version_lt, lte=self.version_lte)
            for v in versions
        )


def build_dependency_index(
    dependency_summary: Optional[Dict[str, Any]],
) -> Dict[str, List[Optional[str]]]:
    """Declared-dependency lookup built from `dependency_scan`'s summary.

    Reads `declared_dependencies` — every dependency the manifests declare,
    not just the ones that matched a framework signature. That distinction is
    the whole point: the libraries these conditions care about
    (commons-collections, jsch, castor) are not frameworks and never appear
    under `frameworks`. The per-framework `matched_dependencies` are folded in
    too so an older summary still resolves.

    Indexed under both the full manifest name and, for coordinate-style names,
    the artifact half — Maven reports `org.apache.struts:struts-core` while a
    rule naturally names just `struts-core`, and both should match.
    """
    summary = dependency_summary or {}
    index: Dict[str, List[Optional[str]]] = {}

    def _add(dep: Dict[str, Any]) -> None:
        name = str(dep.get("name") or "").strip().lower()
        if not name:
            return
        version = dep.get("version")
        for key in {name, name.rsplit(":", 1)[-1]}:
            index.setdefault(key, []).append(version)

    for dep in summary.get("declared_dependencies", []) or []:
        _add(dep)
    for framework in summary.get("frameworks", []) or []:
        for dep in framework.get("matched_dependencies", []) or []:
            _add(dep)
    return index


class RegexRule:
    __slots__ = (
        "id", "title", "description", "cwe", "severity", "category", "owasp",
        "languages", "frameworks", "requires_dependency",
        "pattern", "regex", "multiline", "group_by_rule", "derived",
        "scan_comments", "examples", "issue_class",
    )

    def __init__(self, raw: Dict[str, Any]):
        self.id = raw["id"]
        self.title = raw.get("title", self.id)
        self.description = raw.get("description", "")
        self.cwe = raw.get("cwe", "")
        self.severity = raw.get("severity", "MEDIUM")
        self.category = raw.get("category", "code")
        self.owasp = raw.get("owasp", "")
        # Default grouping keys on (rule_id, matched_text) so a hardcoded
        # secret and a test placeholder that trip the same rule stay visibly
        # separate rows. Some rules match constructs whose text is *expected*
        # to vary per occurrence (a class declaration's name, for instance)
        # while still describing exactly one issue — those opt in here to
        # collapse by rule_id alone, ignoring matched_text.
        self.group_by_rule = bool(raw.get("group_by_rule", False))
        self.derived = bool(raw.get("derived", False))
        # What kind of issue a hit is: security (default), quality or inactive.
        # Validated against llm_file_scan.ISSUE_CLASSES by tests/test_rule_catalog.py
        # (this module cannot import it without a cycle).
        self.issue_class = str(raw.get("issue_class") or "security")
        # Hits that start on a comment-only line are dropped, for line and
        # multiline rules alike. A rule *about* comments opts out.
        self.scan_comments = bool(raw.get("scan_comments", False))
        # {"match": [...], "no_match": [...]}: documentation the catalog test
        # runs through scan_text_by_rule; never read at scan time. An entry is
        # a code string, or {"code": ..., "path": ...} to pick the language.
        self.examples: Dict[str, List[Any]] = dict(raw.get("examples") or {})
        # Empty list = universal (matches every language / every framework).
        # Non-empty = restrict — same convention pipeline/ast_patterns.py
        # already uses for `rule.languages & langs`.
        self.languages: List[str] = list(raw.get("languages") or [])
        self.frameworks: List[str] = list(raw.get("frameworks") or [])
        # Optional: restrict the rule to projects that declare a given library
        # (see DependencyCondition). Empty = unconditional, like the lists above.
        self.requires_dependency: List[DependencyCondition] = [
            DependencyCondition(entry) for entry in (raw.get("requires_dependency") or [])
        ]
        self.pattern = raw["pattern"]
        # Patterns that intentionally span lines ([\s\S], DOTALL-style) need a
        # full-file search — line-by-line would never see across newlines.
        # Do NOT set re.MULTILINE: ^/$ must stay string anchors for whole-file
        # rules like entire-file-block-commented.
        self.multiline = ("[\\s\\S]" in self.pattern) or ("[\\S\\s]" in self.pattern)
        self.regex = re.compile(self.pattern)

    def applies_to(
        self,
        file_lang: Optional[str],
        active_frameworks: Optional[Set[str]],
        dependency_index: Optional[Dict[str, List[Optional[str]]]] = None,
    ) -> bool:
        """A rule applies unless it names a language/framework/dependency
        constraint that the current file/project doesn't match. Empty
        constraints never exclude — that's what lets 90% of rules (secrets,
        generic crypto, generic CORS) stay untagged and keep running
        everywhere, exactly as before these filters were added.

        `dependency_index` left as None means "no dependency data available",
        which never excludes a rule — the constraint is only enforced when we
        actually know what the project declares.
        """
        if self.languages and file_lang not in self.languages:
            return False
        if self.frameworks and not (set(self.frameworks) & (active_frameworks or set())):
            return False
        if self.requires_dependency and dependency_index is not None:
            if not any(cond.matches(dependency_index) for cond in self.requires_dependency):
                return False
        return True


def load_rules(rules_path: Path) -> List[RegexRule]:
    """Compile a rule catalog from a directory of rule files, or a single file.

    A directory loads every `*.json` in it except `surfaces.json` (which holds
    the stack->surface map, not rules), so the catalog can be split by language
    without the loader needing to know the filenames. A single file keeps the
    old behaviour, which is what `state["regex_rules_path"]` overrides and test
    fixtures rely on.

    A missing or malformed *file* raises (FileNotFoundError / JSONDecodeError)
    — the caller asked for a specific rule set and a silent empty result would
    look like "scanned, nothing found" instead of "couldn't load rules". An
    individual rule with a pattern that fails to compile is skipped rather
    than failing the whole set, since one bad entry shouldn't block every
    other rule from running.

    Duplicate ids across files raise: triage looks rules up by id, so a
    collision would silently shadow one rule with another.
    """
    path = Path(rules_path)
    if path.is_dir():
        files = sorted(p for p in path.glob("*.json") if p.name != SURFACES_FILENAME)
        if not files:
            raise FileNotFoundError(f"no rule files found in {path}")
    else:
        files = [path]

    rules: List[RegexRule] = []
    seen: Dict[str, str] = {}
    for rules_file in files:
        raw = json.loads(rules_file.read_text(encoding="utf-8"))
        for entry in raw:
            try:
                rule = RegexRule(entry)
            except re.error:
                continue
            if rule.id in seen:
                raise ValueError(
                    f"duplicate rule id {rule.id!r} in {rules_file.name} "
                    f"(already defined in {seen[rule.id]})"
                )
            seen[rule.id] = rules_file.name
            rules.append(rule)
    return rules


# Language → comment syntax for the regex-only triage matcher. A hit on a line
# that is entirely a comment is almost always a false positive (commented-out
# code, a sed pattern in a docstring, etc.). Kept local: llm_file_scan already
# imports from this module, so the reverse would be circular.
_LINE_COMMENT_PREFIXES: Dict[str, tuple] = {
    "java": ("//",), "typescript": ("//",), "javascript": ("//",),
    "csharp": ("//",), "go": ("//",), "php": ("//", "#"),
    "python": ("#",), "shell": ("#",), "yaml": ("#",),
    "properties": ("#", "!"), "env": ("#",), "terraform": ("#",),
    "ruby": ("#",), "sql": ("--",),
}
_BLOCK_COMMENT_DELIMS: Dict[str, tuple] = {
    "java": ("/*", "*/"), "typescript": ("/*", "*/"), "javascript": ("/*", "*/"),
    "csharp": ("/*", "*/"), "go": ("/*", "*/"), "php": ("/*", "*/"),
    "xml": ("<!--", "-->"), "html": ("<!--", "-->"),
}


def _comment_line_mask(text: str, file_lang: Optional[str]) -> FrozenSet[int]:
    """1-based line numbers that are ENTIRELY a comment.

    Conservative: a line mixing real code with a trailing comment is never
    masked, so a genuine hit is never hidden — only unambiguous full-line
    comments and lines strictly inside a block-comment span are returned. A
    line is only masked as a block-open or block-close line when the opener
    starts the stripped line (or, for a closer, when nothing but whitespace
    follows it). Multiline rules do not use this mask.
    """
    if not file_lang:
        return frozenset()
    lang = str(file_lang).lower()
    line_prefixes = _LINE_COMMENT_PREFIXES.get(lang, ())
    block = _BLOCK_COMMENT_DELIMS.get(lang)
    if not line_prefixes and not block:
        return frozenset()

    open_d, close_d = block if block else (None, None)
    masked: set[int] = set()
    in_block = False

    for lineno, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()

        if in_block:
            if close_d and close_d in stripped:
                after = stripped.split(close_d, 1)[1]
                if after.strip() == "":
                    masked.add(lineno)
                in_block = False
            else:
                masked.add(lineno)
            continue

        if line_prefixes and any(stripped.startswith(p) for p in line_prefixes):
            masked.add(lineno)
            continue

        if not open_d or not stripped.startswith(open_d):
            continue

        rest = stripped[len(open_d):]
        if close_d and close_d in rest:
            after = rest.split(close_d, 1)[1]
            if after.strip() == "":
                masked.add(lineno)
        else:
            masked.add(lineno)
            in_block = True

    return frozenset(masked)


def _snippet(match: re.Match) -> str:
    text = match.group(0).strip()
    if len(text) > _MAX_SNIPPET_LEN:
        text = text[:_MAX_SNIPPET_LEN] + "..."
    return text


def _hit(rule: RegexRule, match: re.Match, text: str) -> Dict[str, Any]:
    lineno = text.count("\n", 0, match.start()) + 1
    return {
        "line": lineno,
        "rule": rule.id,
        "category": rule.category,
        "severity": rule.severity,
        "matched_text": _snippet(match),
    }


def scan_text(
    text: str,
    rules: List[RegexRule],
    *,
    file_lang: Optional[str] = None,
    active_frameworks: Optional[Set[str]] = None,
) -> List[Dict[str, Any]]:
    """Applies every applicable rule to `text` (see RegexRule.applies_to for
    what "applicable" means). Line-oriented rules run per line; multiline
    rules (patterns using [\\s\\S]) run once against the full file."""
    hits: List[Dict[str, Any]] = []
    comment_lines = _comment_line_mask(text, file_lang)
    for rule in rules:
        if not rule.applies_to(file_lang, active_frameworks):
            continue
        hits.extend(scan_text_by_rule(text, rule, comment_lines=comment_lines))
    hits.sort(key=lambda h: (h["line"], h["rule"]))
    return hits


def _read_text(repo_root: Path, rel_path: str) -> Optional[str]:
    try:
        return (repo_root / rel_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def scan_text_by_rule(
    text: str,
    rule: "RegexRule",
    *,
    comment_lines: Optional[FrozenSet[int]] = None,
) -> List[Dict[str, Any]]:
    """Apply a single rule. Multiline rules search the whole file (every
    match, up to MULTILINE_HITS_PER_FILE_CAP); others search line by line.
    Used for slow per-pattern narration.

    `comment_lines` is an optional set of 1-based line numbers that are
    entirely comments; a hit starting on one of those lines is skipped
    unless the rule sets `scan_comments`. Default None means no masking
    (callers that don't pass `file_lang` keep their previous behaviour).
    """
    hits: List[Dict[str, Any]] = []
    mask = None if rule.scan_comments else comment_lines
    if rule.multiline:
        for match in rule.regex.finditer(text):
            hit = _hit(rule, match, text)
            if mask and hit["line"] in mask:
                continue
            hits.append(hit)
            if len(hits) >= MULTILINE_HITS_PER_FILE_CAP:
                break
        return hits

    for lineno, line in enumerate(text.splitlines(), start=1):
        if mask and lineno in mask:
            continue
        match = rule.regex.search(line)
        if not match:
            continue
        hits.append({
            "line": lineno,
            "rule": rule.id,
            "category": rule.category,
            "severity": rule.severity,
            "matched_text": _snippet(match),
        })
    return hits


def scan_one_file(
    repo_root: Path,
    rel_path: str,
    module: str,
    rules: List[RegexRule],
    *,
    file_lang: Optional[str] = None,
    active_frameworks: Optional[Set[str]] = None,
    dependency_index: Optional[Dict[str, List[Optional[str]]]] = None,
    on_rule: Optional[Callable[..., None]] = None,
) -> Dict[str, Any]:
    """Scan a single file with every applicable rule (language- and
    framework-filtered per RegexRule.applies_to — see that method for the
    empty-means-universal convention). Returns hits plus timing and which
    rule ids matched vs stayed clean (for Copilot-style narration).

    If `on_rule` is provided it is called as
    `on_rule(rule_index, rule, hits_for_rule)` after each *applicable* pattern
    so the agent can stream per-rule Observation lines.
    """
    t0 = time.perf_counter()
    text = _read_text(repo_root, rel_path)
    read_error = text is None
    applicable_rules = [
        r for r in rules if r.applies_to(file_lang, active_frameworks, dependency_index)
    ]
    hits: List[Dict[str, Any]] = []
    matched_rules: List[str] = []
    if text is not None:
        comment_lines = _comment_line_mask(text, file_lang)
        for i, rule in enumerate(applicable_rules, start=1):
            rule_hits = scan_text_by_rule(text, rule, comment_lines=comment_lines)
            if on_rule is not None:
                on_rule(i, rule, rule_hits)
            if rule_hits:
                matched_rules.append(rule.id)
                hits.extend(rule_hits)
    elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
    hits.sort(key=lambda h: (h["line"], h["rule"]))
    matched_rules = sorted(set(matched_rules))
    clean_rule_count = len(applicable_rules) - len(matched_rules)
    return {
        "file_path": rel_path,
        "module": module,
        "hits": hits,
        "hit_count": len(hits),
        "elapsed_ms": elapsed_ms,
        "matched_rules": matched_rules,
        "clean_rule_count": clean_rule_count,
        "applicable_rule_count": len(applicable_rules),
        "read_error": read_error,
    }


# --- the regex pass in worker processes ----------------------------------------
#
# The catalog pass is pure-Python regex, so threads serialize on the GIL. On
# large triage sets it runs in worker processes instead. "spawn" is used
# everywhere: forking a process that already runs scan threads can deadlock.
# Workers receive the rules once (initializer), then (path, module, lang,
# rule_ids) jobs; results are exactly what scan_one_file returns in-process.
PROCESS_POOL_MIN_FILES = 500
PROCESS_POOL_WORKERS = max(1, min(8, (os.cpu_count() or 2) - 1))

_WORKER: Dict[str, Any] = {}

ScanJob = Tuple[str, str, Optional[str], Optional[Tuple[str, ...]]]


def _worker_init(rules: List[RegexRule], repo_root: str,
                 active_frameworks: Optional[Set[str]],
                 dependency_index: Optional[Dict[str, List[Optional[str]]]]) -> None:
    _WORKER.update(
        rules=list(rules), by_id={r.id: r for r in rules}, root=Path(repo_root),
        frameworks=active_frameworks, deps=dependency_index,
    )


def _worker_scan(job: ScanJob) -> Dict[str, Any]:
    path, module, lang, rule_ids = job
    rules = _WORKER["rules"] if rule_ids is None else [_WORKER["by_id"][i] for i in rule_ids]
    return scan_one_file(
        _WORKER["root"], path, module, rules, file_lang=lang,
        active_frameworks=_WORKER["frameworks"], dependency_index=_WORKER["deps"],
    )


def scan_files_in_processes(
    jobs: Sequence[ScanJob],
    *,
    repo_root: Path,
    rules: List[RegexRule],
    active_frameworks: Optional[Set[str]] = None,
    dependency_index: Optional[Dict[str, List[Optional[str]]]] = None,
    workers: int = PROCESS_POOL_WORKERS,
) -> Optional[Dict[str, Dict[str, Any]]]:
    """{path: scan_one_file result} for every job, computed in worker
    processes; None if a pool can't be used here (the caller then scans
    in-process, with identical results)."""
    if not jobs:
        return {}
    workers = max(1, min(workers, len(jobs)))
    try:
        with ProcessPoolExecutor(
            max_workers=workers,
            mp_context=multiprocessing.get_context("spawn"),
            initializer=_worker_init,
            initargs=(list(rules), str(repo_root), active_frameworks, dependency_index),
        ) as pool:
            chunksize = max(1, len(jobs) // (workers * 8))
            results = list(pool.map(_worker_scan, jobs, chunksize=chunksize))
    except Exception as exc:  # noqa: BLE001 — fall back, never fail the tier
        print(f"  [regex] worker processes unavailable ({type(exc).__name__}: {exc}); scanning in-process")
        return None
    return {job[0]: result for job, result in zip(jobs, results)}


def scan_files_for_tier(
    module_plan: Dict[str, Any],
    repo_root: Path,
    tier: str,
    rules: List[RegexRule],
    *,
    active_frameworks: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """Regex-scans every file the module/risk map flagged at `tier` (e.g.
    "CRITICAL"). Each result entry carries its module (from module_plan) so
    downstream consumers — LLM verification, the next tier's rollout — can
    group without re-joining against module_plan themselves.

    `active_frameworks` is computed once for the whole project (the set of
    framework labels `stack_signatures.py` matched from the dependency scan)
    and applied to every file — a rule tagged e.g. "Spring Security" only
    fires when Spring Security is actually a recognized dependency of this
    project, regardless of which stack that turns out to be. Each entry's own
    `lang` (set by node_map_modules_and_risk from the file's extension) drives
    the per-file language filter.
    """
    tier = tier.upper()
    entries = [f for f in module_plan.get("files", []) if f.get("risk_level") == tier]

    files_out: List[Dict[str, Any]] = [
        scan_one_file(
            repo_root, entry["path"], entry.get("module", "(root)"), rules,
            file_lang=entry.get("lang"), active_frameworks=active_frameworks,
        )
        for entry in entries
    ]

    return {
        "scanned_tier": tier,
        "total_files": len(entries),
        "total_hits": sum(f["hit_count"] for f in files_out),
        "files": files_out,
    }


# ===========================================================================
# Vulnerability surfaces
# ===========================================================================
#
# The legacy audit docs in regex_data/ all reason the same way:
#
#     Tech Stack Detected -> Known Vulnerability Surface -> Targeted Regex
#
# `surfaces.json` encodes that table so the reasoning is reproducible on any
# repo instead of being prose about one project. A surface is explanatory and
# prioritising, never a gate: rule *execution* is governed solely by
# RegexRule.applies_to, so declaring a surface can never silently drop
# coverage, and a rule named by no surface still runs everywhere it applies.


class Surface:
    """One `stack signal -> vulnerability surface -> rule ids` mapping."""

    __slots__ = ("surface", "rationale", "rules", "languages", "frameworks", "dependencies")

    def __init__(self, raw: Dict[str, Any]):
        self.surface = str(raw["surface"])
        self.rationale = str(raw.get("rationale", ""))
        self.rules: List[str] = list(raw.get("rules") or [])
        when = raw.get("when") or {}
        self.languages: Set[str] = {str(x).lower() for x in (when.get("languages") or [])}
        self.frameworks: List[str] = list(when.get("frameworks") or [])
        self.dependencies: List[DependencyCondition] = [
            DependencyCondition(entry) for entry in (when.get("dependencies") or [])
        ]

    def is_active(
        self,
        *,
        languages: Optional[Set[str]] = None,
        active_frameworks: Optional[Set[str]] = None,
        dependency_index: Optional[Dict[str, List[Optional[str]]]] = None,
    ) -> bool:
        """A surface activates when every `when` clause it declares is met.

        An empty clause is not a constraint. A surface that declares no clause
        at all is always active — that is how the language-agnostic surfaces
        (secrets, generic crypto) stay on for every stack.
        """
        if self.languages and not (self.languages & {str(l).lower() for l in (languages or set())}):
            return False
        if self.frameworks and not (set(self.frameworks) & (active_frameworks or set())):
            return False
        if self.dependencies:
            index = dependency_index or {}
            if not any(cond.matches(index) for cond in self.dependencies):
                return False
        return True


def load_surfaces(rules_path: Path) -> List[Surface]:
    """Load `surfaces.json` from a rules directory. Absent file -> no surfaces
    (the catalog still works; only the narration and ordering are lost)."""
    path = Path(rules_path)
    surfaces_file = path / SURFACES_FILENAME if path.is_dir() else path
    if not surfaces_file.is_file():
        return []
    raw = json.loads(surfaces_file.read_text(encoding="utf-8"))
    return [Surface(entry) for entry in raw]


def active_surfaces(
    surfaces: List[Surface],
    *,
    languages: Optional[Set[str]] = None,
    active_frameworks: Optional[Set[str]] = None,
    dependency_index: Optional[Dict[str, List[Optional[str]]]] = None,
) -> List[Surface]:
    return [
        s for s in surfaces
        if s.is_active(
            languages=languages,
            active_frameworks=active_frameworks,
            dependency_index=dependency_index,
        )
    ]


def surface_rule_ids(surfaces: List[Surface]) -> Set[str]:
    """Every rule id named by the given (already-filtered) surfaces."""
    ids: Set[str] = set()
    for surface in surfaces:
        ids.update(surface.rules)
    return ids


_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Generic SQL-concat catalog entries bias the LLM toward noisy findings — keep
# them out of the prompt guidance (the LLM scan still owns detection; the
# regex triage tier still runs them). API-specific SQL rules (prepareStatement,
# JPA, JdbcTemplate) stay in the prompt.
_SQL_CONCAT_CATALOG_IDS = frozenset({
    "java-sql-string-concat",
    "java-jdbc-statement-exec-variable",
    "java-sql-orderby-param",
})


def rules_for_prompt(
    rules: List[RegexRule],
    file_lang: Optional[str],
    active_frameworks: Optional[Set[str]] = None,
    *,
    max_rules: int = 60,
    dependency_index: Optional[Dict[str, List[Optional[str]]]] = None,
    priority_rule_ids: Optional[Set[str]] = None,
) -> List[Dict[str, Any]]:
    """Compact rule-catalog serializer for the LLM prompt — guidance for what
    to look for (id/title/description/cwe/severity/owasp), never executed as
    a gate. The raw `pattern` regex is deliberately omitted here: it's a
    scan-time construct for this module's own `re.search` pass, not
    something an LLM reading the actual source needs — dropping it shrinks
    the prompt with no loss of guidance. Filters to rules applicable to this
    file's language/frameworks/dependencies (RegexRule.applies_to) to shrink
    the prompt further; if still over `max_rules`, truncates lowest-severity
    entries last (keeps CRITICAL/HIGH first).

    `priority_rule_ids` (typically `surface_rule_ids` for the surfaces this
    project activated) sort first, so when the catalog is truncated it is the
    stack-relevant guidance that survives rather than whatever happened to be
    highest severity.
    """
    priority = priority_rule_ids or set()
    applicable = [
        r for r in rules
        if r.applies_to(file_lang, active_frameworks, dependency_index)
        and r.id not in _SQL_CONCAT_CATALOG_IDS
    ]
    applicable.sort(
        key=lambda r: (r.id not in priority, _SEVERITY_ORDER.get(r.severity, 9))
    )
    if len(applicable) > max_rules:
        applicable = applicable[:max_rules]
    return [
        {
            "id": r.id,
            "title": r.title,
            "description": r.description,
            "cwe": r.cwe,
            "severity": r.severity,
            "owasp": r.owasp,
            "issue_class": r.issue_class,
        }
        for r in applicable
    ]
