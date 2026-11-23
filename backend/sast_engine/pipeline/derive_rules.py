"""derive_rules.py — runtime RegexRules from this scan's analysis.

Pass A (no LLM): project methods that contain a typed Java sink become
Kind-A wrapper patterns (``\\bname\\s*\\(``). A SQL wrapper becomes a rule only
when its method summary (`sql_semantics`, SAST-02-060) shows a *parameter*
reaching SQL text: fixed-bound, zero-argument, getter and stub wrappers derive
nothing. A rule is keyed by the wrapper's owner and signature, so two
same-named methods are two rules, and carries that identity
(`wrapper_owner`, `wrapper_signature`, `tainted_params`); the
`wrapper_call_identity` validator then checks each call resolves to it. Pass B (one LLM call): extra
source/sink API patterns for the detected stack. Both are merged onto the
static ``rules/`` catalog — never written back to disk, never a replacement.

Catalog rules always win on id or normalized-pattern collision.
"""

from __future__ import annotations

import hashlib
import json
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from llm_client import call_llm, parse_llm_json_array

from pipeline.call_graph_common import GraphAdapter
from pipeline.owasp_map import owasp_for_rule
from pipeline.regex_scan import RegexRule, clean_text, normalize_cwe

DEFAULT_MAX_DERIVED = 50
MAX_PATTERN_CHARS = 200
MAX_SAMPLE_TYPES = 20
LLM_STEP = "derive_runtime_rules"

# Per-language name sets: names too generic to make a useful wrapper pattern
# (_GENERIC_NAMES_BY_LANG) and names that are themselves the sink API rather
# than a project wrapper around one (_SINK_METHOD_NAMES_BY_LANG). Keyed by
# `GraphAdapter.language`; "java" is the default when no adapter is passed,
# to preserve this function's original (Java-only) behavior exactly.
_GENERIC_NAMES_BY_LANG: Dict[str, frozenset] = {
    "java": frozenset({
        "get", "set", "find", "save", "update", "delete", "build", "equals",
        "toString", "hashCode", "of", "from", "valueOf", "main",
    }),
    "python": frozenset({
        "get", "set", "save", "update", "delete", "__init__", "__str__",
        "__repr__", "main",
    }),
}
_SINK_METHOD_NAMES_BY_LANG: Dict[str, frozenset] = {
    "java": frozenset({
        "executeQuery", "executeUpdate", "execute", "executeBatch", "executeLargeUpdate",
        "createQuery", "createNativeQuery", "getResultList", "getSingleResult",
        "query", "update", "exec", "start", "command", "readObject",
        "write", "writeString", "newInputStream", "getRuntime",
    }),
    "python": frozenset({
        "execute", "executemany", "run", "system", "popen", "loads", "load",
        "urlopen", "eval", "exec", "compile",
    }),
}
_SINK_KIND_CWE = {
    "sql": "CWE-89",
    "jpa": "CWE-89",
    "jdbc_template": "CWE-89",
    "command": "CWE-78",
    "deser": "CWE-502",
    "files": "CWE-22",
}
_SINK_KIND_SEVERITY = {
    "sql": "HIGH",
    "jpa": "HIGH",
    "jdbc_template": "HIGH",
    "command": "HIGH",
    "deser": "MEDIUM",
    "files": "MEDIUM",
}

# Wrapper candidates are ranked by sink severity before the cap, so on a large
# repo the slots go to SQL/command wrappers (selectCount(String), runScript)
# rather than whichever kind the graph happened to list first. Unknown kinds
# rank last.
_SINK_KIND_RANK = {
    "sql": 0, "jpa": 0, "jdbc_template": 0,
    "command": 1,
    "deser": 2,
    "files": 3,
}

_NESTED_QUANTIFIERS = re.compile(r"[*+][+*]")
_LEADING_FLAGS = re.compile(r"^\(\?[aiLmsux]+\)")

_PASS_B_SYSTEM = (
    "You are a senior application security engineer. Given a project's tech "
    "stack, active vulnerability surfaces, and (when present) custom Java "
    "wrapper method names already derived from a call graph, propose extra "
    "regex patterns that locate THIS project's source or sink APIs.\n\n"
    "Rules:\n"
    "- Kind A only: a single API/call site (source or sink). Do NOT write "
    "source-then-sink flow patterns (no [\\s\\S] windows between two calls).\n"
    "- Do not emit a pattern that is the same regex as a catalog rule.\n"
    "- Prefer project-specific wrappers and unusual names, not JDK/framework "
    "methods the catalog already covers.\n"
    "- Each pattern must be a valid Python regex, under 200 characters, with "
    "a word boundary on the identifier. No nested *+ or .*.* (ReDoS).\n"
    "- Respond with one JSON object {\"rules\": [...]} only (an empty list "
    "if nothing project-specific is worth adding). No prose, no markdown fences."
)


def _norm_pattern(pattern: str) -> str:
    s = _LEADING_FLAGS.sub("", (pattern or "").strip())
    return re.sub(r"\s+", "", s)


try:  # Python 3.11+; the structural ReDoS check needs the parse tree
    import re._constants as _sre_const
    import re._parser as _sre_parse
except ImportError:  # pragma: no cover — older interpreters
    _sre_const = _sre_parse = None  # type: ignore[assignment]

# A pattern is a few characters of identifier, not a program. The check below
# works on the parse tree, not on the text, because a model asked for a
# "word-bounded API name" can still return `(\w+\s?)+$` or `(a|aa)+$` — which
# pass any list of banned substrings and take exponential time on a long line.
_PROBE_ALPHABET = frozenset(chr(i) for i in range(32, 127)) | {"\t", "\n"}
_WILDCARD_MIN_CHARS = 80  # a repeated class this wide (`.`, `[^)]`, `\S`) is a wildcard
_LARGE_REPEAT = 20


def _category_chars(category: Any) -> frozenset:
    name = str(category).replace("UNI_", "")
    positive = {
        "CATEGORY_DIGIT": str.isdigit,
        "CATEGORY_SPACE": str.isspace,
        "CATEGORY_WORD": lambda c: c.isalnum() or c == "_",
    }
    if name in positive:
        return frozenset(c for c in _PROBE_ALPHABET if positive[name](c))
    base = name.replace("NOT_", "")
    if name != base and base in positive:
        return _PROBE_ALPHABET - frozenset(c for c in _PROBE_ALPHABET if positive[base](c))
    return _PROBE_ALPHABET


def _item_chars(op: Any, av: Any) -> Optional[frozenset]:
    """The characters a single-character parse item can match (None: not one)."""
    c = _sre_const
    if op == c.LITERAL:
        return frozenset({chr(av)})
    if op == c.NOT_LITERAL:
        return _PROBE_ALPHABET - {chr(av)}
    if op == c.ANY:
        return _PROBE_ALPHABET - {"\n"}
    if op == c.CATEGORY:
        return _category_chars(av)
    if op == c.IN:
        chars: Set[str] = set()
        negate = False
        for inner_op, inner_av in av:
            if inner_op == c.NEGATE:
                negate = True
            elif inner_op == c.LITERAL:
                chars.add(chr(inner_av))
            elif inner_op == c.RANGE:
                chars |= {ch for ch in _PROBE_ALPHABET if inner_av[0] <= ord(ch) <= inner_av[1]}
            elif inner_op == c.CATEGORY:
                chars |= _category_chars(inner_av)
        return (_PROBE_ALPHABET - chars) if negate else frozenset(chars & _PROBE_ALPHABET)
    return None


def _repeat_parts(op: Any, av: Any) -> Optional[Tuple[int, int, Any]]:
    c = _sre_const
    repeats = (c.MAX_REPEAT, c.MIN_REPEAT, getattr(c, "POSSESSIVE_REPEAT", c.MAX_REPEAT))
    return (av[0], av[1], av[2]) if op in repeats else None


def _children(op: Any, av: Any) -> List[Any]:
    """The sub-patterns (lists of parse items) directly under one parse item."""
    c = _sre_const
    if op == c.BRANCH:
        return list(av[1])
    if op == c.SUBPATTERN:
        return [av[-1]]
    if op in (c.ASSERT, c.ASSERT_NOT):
        return [av[1]]
    if op == getattr(c, "ATOMIC_GROUP", None):
        return [av]
    return []


def _has_repeat_or_branch(items: Any) -> bool:
    c = _sre_const
    for op, av in items:
        parts = _repeat_parts(op, av)
        if parts and parts[1] > 1:
            return True
        if op == c.BRANCH and len(av[1]) > 1:
            return True
        if any(_has_repeat_or_branch(child) for child in _children(op, av)):
            return True
        if parts and _has_repeat_or_branch(parts[2]):
            return True
    return False


def _redos_walk(items: Any, wildcards: List[int]) -> Optional[str]:
    c = _sre_const
    previous: Optional[frozenset] = None  # chars of the last unbounded repeat with nothing consumed since
    for op, av in items:
        parts = _repeat_parts(op, av)
        if parts is not None:
            lo, hi, sub = parts
            if hi > 1 and _has_repeat_or_branch(sub):
                return "nested_quantifier"
            inner = _redos_walk(sub, wildcards)
            if inner:
                return inner
            if hi == c.MAXREPEAT or hi > _LARGE_REPEAT:
                chars = _item_chars(*sub[0]) if len(sub) == 1 else None
                chars = chars if chars is not None else _PROBE_ALPHABET
                if previous is not None and previous & chars:
                    return "adjacent_overlapping_repeats"
                if len(chars) >= _WILDCARD_MIN_CHARS:
                    wildcards[0] += 1
                    if wildcards[0] > 1:
                        return "multiple_wildcards"
                previous = chars
            elif lo > 0:
                previous = None  # a mandatory piece sits between repeats
            continue
        if op in (c.GROUPREF, getattr(c, "GROUPREF_EXISTS", None)):
            return "backreference"
        if op == c.AT:
            continue  # zero-width
        children = _children(op, av)
        for child in children:
            inner = _redos_walk(child, wildcards)
            if inner:
                return inner
        previous = None
    return None


def redos_reason(pattern: str) -> Optional[str]:
    """Why `pattern` could take super-linear time, or None. Conservative on purpose:
    a derived pattern is one API name with a word boundary, so rejecting a nested
    quantifier, an alternation inside a repeat, two adjacent overlapping unbounded
    repeats, two wildcards, or a backreference costs nothing real."""
    if _sre_parse is None:
        return "no_parser" if re.search(r"[)\]}][*+{]", pattern) else None
    try:
        tree = _sre_parse.parse(pattern)
    except (re.error, RecursionError, OverflowError):
        return None  # not a valid pattern: compile_error reports it
    return _redos_walk(tree.data if hasattr(tree, "data") else tree, [0])


def pattern_is_unsafe(pattern: str) -> Optional[str]:
    """Return a reason string if `pattern` must not be compiled for scanning."""
    if not pattern or not str(pattern).strip():
        return "empty"
    if len(pattern) > MAX_PATTERN_CHARS:
        return "too_long"
    if ".*.*" in pattern or ".+.*" in pattern or ".*+" in pattern:
        return "redos"
    if _NESTED_QUANTIFIERS.search(pattern):
        return "redos"
    if re.search(r"\([^()]*[+*]\)[+*]", pattern):
        return "redos"
    # A whole-file ([\s\S]) pattern runs over the entire file instead of one
    # line, and the prompt asks for single-call patterns only.
    if "[\\s\\S]" in pattern or "[\\S\\s]" in pattern:
        return "multiline"
    if redos_reason(pattern):
        return "redos"
    if not re.search(r"[A-Za-z_]", pattern):
        return "no_identifier"
    return None


def _sanitize_id_fragment(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "-", name).strip("-")
    return cleaned or "unnamed"


_SQL_SINK_KINDS = frozenset({"sql", "jpa", "jdbc_template"})


def _wrapper_id(kind: str, name: str, owner: str, signature: str) -> str:
    """Stable and unique per wrapper: `runtime-sink-<kind>-<name>-<8 hex>` of
    owner and signature. A graph that knows no owner keeps the plain id."""
    base = f"runtime-sink-{kind}-{_sanitize_id_fragment(name)}"
    if not owner:
        return base
    return f"{base}-{hashlib.sha1(f'{owner}#{signature}'.encode('utf-8')).hexdigest()[:8]}"


def wrappers_from_graph(
    graph: Optional[GraphAdapter], *, stats: Optional[Dict[str, int]] = None
) -> List[Dict[str, Any]]:
    """Pass A: one Kind-A rule dict per distinct (wrapper identity, sink
    kind), most severe sink kind first, then by name and id (a stable order
    keeps the derived set — and the prompts that embed it — identical across
    reruns). `stats` gets `candidates` (wrappers before the identity filter)
    and `derived`."""
    if graph is None:
        return []
    language = getattr(graph, "language", "java") or "java"
    generic_names = _GENERIC_NAMES_BY_LANG.get(language, _GENERIC_NAMES_BY_LANG["java"])
    sink_method_names = _SINK_METHOD_NAMES_BY_LANG.get(language, _SINK_METHOD_NAMES_BY_LANG["java"])
    summary_of = getattr(graph, "sql_summary", None)
    seen: Set[Tuple[Any, ...]] = set()
    candidates: Set[Tuple[Any, ...]] = set()
    raw: List[Dict[str, Any]] = []
    for hit in graph.sink_hits():
        caller = graph.caller_info(hit.caller_key)
        if caller is None:
            continue
        if caller.is_constructor:
            continue
        if graph.is_test_path(caller.file):
            continue
        name = caller.name or ""
        if len(name) < 5 or name in generic_names or name in sink_method_names:
            continue
        kind = hit.kind or "sql"
        owner = getattr(caller, "owner", "") or ""
        param_types = tuple(getattr(caller, "param_types", ()) or ())
        arity = getattr(caller, "arity", None)
        signature = f"{name}({','.join(param_types)})"
        key = (owner or name.lower(), signature if owner else "", kind)
        if key in seen or key in candidates:
            continue
        candidates.add(key)
        # A wrapper called with no arguments passes nothing to its sink.
        if arity == 0:
            continue
        tainted: Optional[List[int]] = None
        if kind in _SQL_SINK_KINDS and summary_of is not None and getattr(caller, "key", ""):
            summary = summary_of(caller.key)
            if summary is None or summary.executes != "dynamic" or not summary.positions:
                continue  # fixed-bound, getter, stub: no parameter reaches SQL text
            tainted = list(summary.positions)
        seen.add(key)
        cwe = _SINK_KIND_CWE.get(kind, "CWE-89")
        severity = _SINK_KIND_SEVERITY.get(kind, "MEDIUM")
        entry: Dict[str, Any] = {
            "id": _wrapper_id(kind, name, owner, signature),
            "title": f"Project wrapper {name} reaches a {kind} sink",
            "description": (
                f"{caller.display} contains a typed {kind} sink; call sites "
                f"of this method may carry the same taint."
            ),
            "cwe": cwe,
            "severity": severity,
            "category": "code",
            "owasp": owasp_for_rule(cwe, "code"),
            "languages": [language],
            "frameworks": [],
            "pattern": rf"\b{re.escape(name)}\s*\(",
            "group_by_rule": True,
            "derived": True,
            "wrapper_name": name,
            "sink_kind": kind,
        }
        if owner:
            entry.update(wrapper_owner=owner, wrapper_signature=signature, wrapper_arity=arity)
            if tainted is not None:
                entry["tainted_params"] = tainted
        raw.append(entry)
    if stats is not None:
        stats["candidates"] = stats.get("candidates", 0) + len(candidates)
        stats["derived"] = stats.get("derived", 0) + len(raw)
    raw.sort(key=lambda r: (
        _SINK_KIND_RANK.get(r["sink_kind"], len(_SINK_KIND_RANK)), r["wrapper_name"].lower(), r["id"],
    ))
    return raw


def sample_type_names(graph: Optional[GraphAdapter], *, limit: int = MAX_SAMPLE_TYPES) -> List[str]:
    if graph is None:
        return []
    return graph.type_names(limit=limit)


def compile_derived_rule(
    raw: Dict[str, Any],
    *,
    catalog_ids: Set[str],
    catalog_patterns: Set[str],
    seen_ids: Set[str],
    seen_patterns: Set[str],
    dropped: Optional[List[str]] = None,
) -> Optional[RegexRule]:
    """Compile one derived rule, or None if it collides / is unsafe / invalid.

    `dropped`, when passed, gets one reason string appended per rejected
    candidate — the UI-facing "N candidate(s) failed" breakdown reads this."""
    entry = dict(raw)
    rule_id = str(entry.get("id") or "").strip()
    pattern = str(entry.get("pattern") or "")
    if not rule_id or rule_id in catalog_ids or rule_id in seen_ids:
        if dropped is not None:
            dropped.append("duplicate_id" if rule_id else "missing_id")
        return None
    unsafe = pattern_is_unsafe(pattern)
    if unsafe:
        if dropped is not None:
            dropped.append(f"unsafe_pattern:{unsafe}")
        return None
    norm = _norm_pattern(pattern)
    # Two wrappers of the same name and different owners share a pattern; the
    # identity validator tells their call sites apart, so both are kept.
    pattern_key = f"{norm}|{entry['wrapper_owner']}#{entry.get('wrapper_signature')}" if entry.get(
        "wrapper_owner") else norm
    if not norm or norm in catalog_patterns or pattern_key in seen_patterns:
        if dropped is not None:
            dropped.append("duplicate_pattern")
        return None
    invalid = _validate_entry(entry)
    if invalid:
        if dropped is not None:
            dropped.append(invalid)
        return None
    entry["derived"] = True
    try:
        rule = RegexRule(entry)
    except (re.error, KeyError, TypeError, AttributeError, ValueError):
        if dropped is not None:
            dropped.append("compile_error")
        return None
    seen_ids.add(rule.id)
    seen_patterns.add(pattern_key)
    return rule


def compile_derived_rules(
    raw_rules: Sequence[Dict[str, Any]],
    static_rules: Sequence[RegexRule],
    *,
    cap: int = DEFAULT_MAX_DERIVED,
    dropped: Optional[List[str]] = None,
) -> List[RegexRule]:
    """Compile derived dicts; catalog wins on id or normalized pattern; cap total.

    `dropped`, when passed, collects one reason string per candidate that
    didn't make it in — a candidate never reached because the cap was
    already full is recorded as "over_cap" rather than a validation failure."""
    catalog_ids = {r.id for r in static_rules}
    catalog_patterns = {_norm_pattern(r.pattern) for r in static_rules}
    seen_ids: Set[str] = set()
    seen_patterns: Set[str] = set()
    out: List[RegexRule] = []
    limit = max(0, int(cap))
    for raw in raw_rules:
        if len(out) >= limit:
            if dropped is not None:
                dropped.append("over_cap")
            continue
        try:
            rule = compile_derived_rule(
                raw,
                catalog_ids=catalog_ids,
                catalog_patterns=catalog_patterns,
                seen_ids=seen_ids,
                seen_patterns=seen_patterns,
                dropped=dropped,
            )
        except Exception:  # noqa: BLE001 — one malformed candidate must not abort the rest
            rule = None
            if dropped is not None:
                dropped.append("compile_error")
        if rule is not None:
            out.append(rule)
    return out


def _coerce_rule_items(items: Iterable[Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for item in items:
        if isinstance(item, dict) and item.get("pattern"):
            out.append(item)
    return out


# The only fields a model may set on a rule it proposes (LLM04). Everything else a
# RegexRule understands changes what a rule *does* — `scan_comments` un-masks
# comments, `group_by_rule`/`issue_class`/`category` change how hits are grouped
# and reported, `wrapper_*`/`tainted_params` make a rule a call-identity rule,
# `requires_dependency` can switch it off, `examples` is documentation — and is
# set only by this module's own (Pass A) code.
PASS_B_ALLOWED_FIELDS = (
    "id", "title", "description", "cwe", "severity", "owasp", "languages", "frameworks", "pattern",
)


def _ensure_runtime_llm_id(raw: Dict[str, Any], index: int) -> Dict[str, Any]:
    entry = {key: raw[key] for key in PASS_B_ALLOWED_FIELDS if key in raw}
    rid = str(entry.get("id") or "").strip()
    if not rid.startswith("runtime-llm-"):
        suffix = _sanitize_id_fragment(rid) if rid else str(index)
        entry["id"] = f"runtime-llm-{suffix}"
    entry["derived"] = True
    return entry


_RULE_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")  # Finding.rule_id is String(80)
_CWE_RE = re.compile(r"^CWE-\d{1,5}$")
_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})
_LABEL_RE = re.compile(r"^[A-Za-z0-9_.+\- ]{1,40}$")
MAX_TITLE_CHARS = 200
MAX_DESCRIPTION_CHARS = 500
MAX_LABELS = 10


def _validate_entry(entry: Dict[str, Any]) -> Optional[str]:
    """Normalise the descriptive fields of a derived rule in place; the reason
    it must be rejected, or None."""
    if not _RULE_ID_RE.match(str(entry.get("id") or "")):
        return "invalid_id"
    severity = str(entry.get("severity") or "MEDIUM").strip().upper()
    if severity not in _SEVERITIES:
        return "invalid_severity"
    cwe = normalize_cwe(entry.get("cwe"))
    if not _CWE_RE.match(cwe):
        return "invalid_cwe"
    for key in ("languages", "frameworks"):
        labels = entry.get(key) or []
        if not isinstance(labels, (list, tuple)) or len(labels) > MAX_LABELS or not all(
            isinstance(label, str) and _LABEL_RE.match(label) for label in labels
        ):
            return "invalid_field"
        entry[key] = list(labels)
    entry["severity"], entry["cwe"] = severity, cwe
    entry["title"] = clean_text(entry.get("title") or entry["id"], MAX_TITLE_CHARS)
    entry["description"] = clean_text(entry.get("description"), MAX_DESCRIPTION_CHARS)
    entry["owasp"] = clean_text(entry.get("owasp"), 80)
    return None


def derived_rules_sha256(rules: Iterable[RegexRule]) -> str:
    """Hash of the derived rule set (what each rule matches and says), in id
    order — recorded with the scan so a different derived set is visible."""
    canonical = json.dumps(
        [
            [r.id, r.pattern, r.cwe, r.severity, r.title, r.description, list(r.languages), list(r.frameworks)]
            for r in sorted(rules, key=lambda rule: rule.id)
        ],
        ensure_ascii=False, separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# One derived rule costs about 170 output tokens (id, title, description, cwe,
# severity, owasp, languages, frameworks, pattern). Asking for 50 against the
# default 4096-token ceiling cut the response off after ~24 rules every scan —
# and a truncated answer is never stored in the result cache, so derivation
# reran each time and the deep-scan system prompt (which embeds derived
# rules) changed with it. Ask for a number that fits and size the ceiling to
# match instead.
PASS_B_MAX_RULES_PER_CALL = 30
PASS_B_TOKENS_PER_RULE = 220
PASS_B_TOKEN_HEADROOM = 400
PASS_B_MAX_TOKENS_CEILING = 8192

# Pass B is split into small calls, a few surfaces each, instead of one call for
# the whole stack. Every call then asks for a few rules (a short answer that
# fits any provider's output ceiling and read timeout, and parses reliably on a
# small model), carries only the catalog ids of its own surfaces, and has its
# own result-cache entry. These are fixed numbers, not per-provider ones.
PASS_B_SURFACES_PER_CALL = 3
PASS_B_RULES_PER_SURFACE = 4
PASS_B_MAX_CATALOG_IDS_PER_CALL = 25
PASS_B_MAX_PARALLEL_CALLS = 8


def plan_pass_b_batches(
    surfaces: Sequence[str],
    surface_rules: Optional[Mapping[str, Sequence[str]]],
    remaining_slots: int,
) -> List[Dict[str, Any]]:
    """Pure: the Pass B calls to make, in a stable order.

    Surfaces are sorted (so the same stack always plans the same calls, and a
    rerun hits the result cache), chunked `PASS_B_SURFACES_PER_CALL` at a time,
    and each call is asked for at most `PASS_B_RULES_PER_SURFACE` rules per
    surface, trimmed so the calls together never ask for more than
    `remaining_slots`. No surfaces: one call, as before. Each batch is
    `{"surfaces": [...], "catalog_ids": [...], "limit": n}`.
    """
    slots = min(max(0, int(remaining_slots)), PASS_B_MAX_RULES_PER_CALL * PASS_B_MAX_PARALLEL_CALLS)
    if slots <= 0:
        return []
    names = sorted({str(s) for s in surfaces if str(s).strip()})
    if not names:
        return [{"surfaces": [], "catalog_ids": [], "limit": min(slots, PASS_B_MAX_RULES_PER_CALL)}]
    per_surface = min(PASS_B_RULES_PER_SURFACE, max(1, slots // len(names)))
    rules_of = surface_rules or {}
    batches: List[Dict[str, Any]] = []
    left = slots
    for start in range(0, len(names), PASS_B_SURFACES_PER_CALL):
        if left <= 0 or len(batches) >= PASS_B_MAX_PARALLEL_CALLS:
            break
        chunk = names[start:start + PASS_B_SURFACES_PER_CALL]
        ids: List[str] = []
        for name in chunk:
            for rid in rules_of.get(name) or ():
                if rid not in ids:
                    ids.append(rid)
        limit = min(per_surface * len(chunk), PASS_B_MAX_RULES_PER_CALL, left)
        left -= limit
        batches.append({
            "surfaces": chunk,
            "catalog_ids": ids[:PASS_B_MAX_CATALOG_IDS_PER_CALL],
            "limit": limit,
        })
    return batches


def _pass_b_user_prompt(
    batch: Mapping[str, Any],
    *,
    stack_context: str,
    frameworks: Sequence[str],
    pass_a_names: Sequence[str],
    sample_types: Sequence[str],
) -> str:
    surfaces = list(batch["surfaces"])
    lines = [
        f"Tech stack: {stack_context or 'unknown'}",
        f"Frameworks: {', '.join(frameworks) or 'none'}",
    ]
    if surfaces:
        lines.append(f"Surfaces for this call: {'; '.join(surfaces)}")
        if batch["catalog_ids"]:
            lines.append(
                "Catalog rules already covering these surfaces (do not re-derive): "
                + ", ".join(batch["catalog_ids"])
            )
    else:
        lines.append("Active surfaces: none")
    lines += [
        f"Already-derived wrapper names: {', '.join(pass_a_names) or 'none'}",
        f"Project type names (sample): {', '.join(sample_types) or 'none'}",
        f"Return at most {batch['limit']} objects.",
        "",
        "Each object fields: id, title, description, cwe, severity, owasp, "
        "languages (array), frameworks (array), pattern.",
    ]
    return "\n".join(lines) + "\n"


def _pass_b_call(
    user: str,
    limit: int,
    *,
    usage: Optional[Dict[str, Any]],
    llm_provider: Optional[str],
    llm_model: Optional[str],
    call_llm_fn: Callable[..., str],
) -> List[Dict[str, Any]]:
    """One Pass B call: its parsed rule items, retried once on a parse failure."""
    max_tokens = min(
        PASS_B_MAX_TOKENS_CEILING,
        limit * PASS_B_TOKENS_PER_RULE + PASS_B_TOKEN_HEADROOM,
    )
    raw_text = call_llm_fn(
        _PASS_B_SYSTEM, user, usage=usage, step=LLM_STEP,
        provider=llm_provider, model=llm_model, json_mode=True,
        max_tokens=max_tokens,
    )
    items, parse_err = parse_llm_json_array(raw_text)
    if parse_err and not items:
        raw_text = call_llm_fn(
            _PASS_B_SYSTEM, user + '\n\nReturn the {"rules": [...]} JSON object only.',
            usage=usage, step=LLM_STEP,
            provider=llm_provider, model=llm_model, json_mode=True,
            max_tokens=max_tokens,
        )
        items, parse_err = parse_llm_json_array(raw_text)
    if isinstance(items, dict):
        items = items.get("rules") or []
    return _coerce_rule_items(items)


def llm_derive_rules(
    *,
    stack_context: str,
    frameworks: Sequence[str],
    surfaces: Sequence[str],
    pass_a_names: Sequence[str],
    sample_types: Sequence[str],
    remaining_slots: int,
    surface_rules: Optional[Mapping[str, Sequence[str]]] = None,
    usage: Optional[Dict[str, Any]] = None,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    call_llm_fn: Callable[..., str] = call_llm,
    stats: Optional[Dict[str, int]] = None,
) -> List[Dict[str, Any]]:
    """Pass B: a few small calls (`plan_pass_b_batches`), run together.

    The calls go through `call_llm`, so the concurrency limiter, cost cutoff,
    cancel check and result cache apply to each one on every provider. A call
    that fails (including an exhausted budget or a cancel) contributes no
    rules and never costs the others'. Results are merged in plan order, so
    the same inputs always give the same list.
    """
    batches = plan_pass_b_batches(surfaces, surface_rules, remaining_slots)
    if not batches:
        return []
    prompts = [
        _pass_b_user_prompt(
            batch, stack_context=stack_context, frameworks=frameworks,
            pass_a_names=pass_a_names, sample_types=sample_types,
        )
        for batch in batches
    ]

    def run(index: int) -> Optional[List[Dict[str, Any]]]:
        try:
            return _pass_b_call(
                prompts[index], batches[index]["limit"], usage=usage,
                llm_provider=llm_provider, llm_model=llm_model, call_llm_fn=call_llm_fn,
            )
        except Exception:  # noqa: BLE001 — one failed call must not cost the others
            return None

    if len(batches) == 1:
        results = [run(0)]
    else:
        with ThreadPoolExecutor(max_workers=min(len(batches), PASS_B_MAX_PARALLEL_CALLS)) as pool:
            results = list(pool.map(run, range(len(batches))))

    merged: List[Dict[str, Any]] = []
    failed = 0
    for items in results:
        if items is None:
            failed += 1
            continue
        merged.extend(items)
    if stats is not None:
        stats["pass_b_calls"] = len(batches)
        stats["pass_b_failed_calls"] = failed
        stats["pass_b_returned"] = len(merged)
    return [_ensure_runtime_llm_id(entry, i) for i, entry in enumerate(merged, start=1)]


def derive_runtime_rules(
    *,
    graph: Optional[GraphAdapter] = None,
    static_rules: Sequence[RegexRule] = (),
    stack_context: str = "",
    frameworks: Optional[Sequence[str]] = None,
    surfaces: Optional[Sequence[str]] = None,
    surface_rules: Optional[Mapping[str, Sequence[str]]] = None,
    use_llm: bool = False,
    usage: Optional[Dict[str, Any]] = None,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    max_rules: int = DEFAULT_MAX_DERIVED,
    call_llm_fn: Callable[..., str] = call_llm,
    dropped: Optional[List[str]] = None,
    stats: Optional[Dict[str, int]] = None,
) -> List[RegexRule]:
    """Pass A then Pass B, catalog-preserving merge, capped at `max_rules`.

    Pass A is preferred when trimming. Pass B is skipped when `use_llm` is false.

    `dropped`, when passed, ends up holding one reason string per candidate
    that didn't make the final compiled set — reflects whichever pass(es)
    actually produced the returned rules, not double-counted across passes.
    """
    cap = max(0, int(max_rules))
    pass_a_raw = wrappers_from_graph(graph, stats=stats)
    pass_a_dropped: List[str] = []
    compiled = compile_derived_rules(pass_a_raw, static_rules, cap=cap, dropped=pass_a_dropped)
    if not use_llm or len(compiled) >= cap:
        if dropped is not None:
            dropped.extend(pass_a_dropped)
        return compiled

    pass_a_names = [str(raw.get("wrapper_name") or raw.get("id")) for raw in pass_a_raw]
    try:
        pass_b_raw = llm_derive_rules(
            stack_context=stack_context,
            frameworks=list(frameworks or []),
            surfaces=list(surfaces or []),
            surface_rules=surface_rules,
            pass_a_names=pass_a_names,
            sample_types=sample_type_names(graph),
            remaining_slots=cap - len(compiled),
            usage=usage,
            llm_provider=llm_provider,
            llm_model=llm_model,
            call_llm_fn=call_llm_fn,
            stats=stats,
        )
    except Exception:  # noqa: BLE001 — derive must not fail the scan
        if dropped is not None:
            dropped.extend(pass_a_dropped)
        return compiled
    combined_raw = pass_a_raw + pass_b_raw
    return compile_derived_rules(combined_raw, static_rules, cap=cap, dropped=dropped)
