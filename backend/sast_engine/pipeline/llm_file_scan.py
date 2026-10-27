"""llm_file_scan.py — LLM-primary deep scan plus regex-gated triage.

CRITICAL / HIGH files (`LLM_RISK_LEVELS`, `scan_deep_files`): the LLM owns
detection. The rule catalog in `rules/` is used only as *guidance*
(title/cwe/severity/owasp), never executed as a pre-pass or a gate. Every file
at those risk levels is scanned regardless of whether any regex would match.

MEDIUM / LOW files (`TRIAGE_RISK_LEVELS`, `scan_triage_files`): regex patterns
run first, locally. A file with zero hits is skipped entirely — no LLM call and
no writer call. A file with hits sends only those hit candidates plus a
±CONTEXT_LINES window around each one; the whole file body is never uploaded.
The LLM's only job there is TP/FP on the candidates it was handed, and
`_hit_matches_finding` drops anything it invents outside them.

Per-file flow: size check -> single call or method-boundary chunks -> each
chunk gets (a) a cache-stable system block holding the rule catalog + stack
context and (b) a user block holding a file skeleton and the numbered code ->
LLM returns true_positive/false_positive findings with source/sink/data_flow,
a confidence score, and a required `verdict_reason` (kept for false positives
too, for rule/prompt tuning) -> re-anchor lines -> merge+dedupe within the
file -> enrich snippets -> evidence-based suppression -> one write.

Design notes vs. the previous revision
--------------------------------------
* Suppression is evidence-based, not id-based. A real SQLi tagged with a
  generic catalog id is no longer deleted outright; it survives when the
  surrounding source shows query construction, the model named an untrusted
  source, or confidence is high.
* Suppression runs *after* snippet enrichment, so a sink-only snippet whose
  query is built 20 lines earlier is judged against the real context window.
* Each chunk prompt carries a file skeleton (imports, declarations, and every
  taint source/sink line in the file) so cross-chunk flows stay visible.
* Chunk/file scanning is concurrent under one global in-flight cap.
* JSON parse failures retry once and are recorded, never silently swallowed.
"""

from __future__ import annotations

import json
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from llm_client import (
    PROVIDER_BEDROCK,
    LlmBudgetExhausted,
    append_record,
    bump_counter,
    call_llm,
    stage_has_budget,
    last_call_was_cache_hit,
    parse_llm_json_array,
    record_verdict_event,
    should_cache_system_prompt,
)

from . import reachability
from .finding_facts import prepare_findings, source_in_text
from . import explanation_check
from . import output_sinks
from .occurrence_facts import semantic_signature
from .validators import reapply_precedence, render_deterministic_facts
from .owasp_map import OWASP_TOP_10_2021, owasp_for_rule
from .regex_scan import (
    PROCESS_POOL_MIN_FILES,
    RegexRule,
    _SQL_CONCAT_CATALOG_IDS,
    rules_for_prompt,
    scan_files_in_processes,
    scan_one_file,
)

# --- tunables ---------------------------------------------------------------

CONTEXT_LINES_BEFORE = 10
CONTEXT_LINES_AFTER = 10
SNIPPET_MAX_CHARS = 2400

# Files at or under this many characters get a single LLM call; larger files
# are split into method-boundary chunks. Raised substantially from the old
# 9k/220 — fewer round trips and, more importantly, source and sink are far
# more likely to land in the same chunk.
SINGLE_CALL_CHAR_BUDGET = 24_000
CHUNK_LINE_BUDGET = 450
OVERLAP_LINES = 30

# Skeleton: compact whole-file map prepended to every chunk of a chunked file.
# SKELETON_MAX_LINES bounds what is *collected* for the whole file; each chunk
# then gets only the entries outside its own line range, capped at
# SKELETON_CHUNK_MAX_CHARS (taint source/sink lines first) — lines already in
# the chunk are never sent twice.
SKELETON_MAX_LINES = 400
SKELETON_LINE_MAX_CHARS = 200
SKELETON_CHUNK_MAX_CHARS = 6_000

# A leading license/copyright comment of at least this many lines is replaced
# in the prompt by a one-line marker (original line numbers are preserved).
LICENSE_HEADER_MIN_LINES = 3

# Concurrency. MAX_INFLIGHT_LLM_CALLS bounds *total* simultaneous calls across
# both pools, so nesting file workers and chunk workers cannot stampede a
# provider rate limit. Dial down if you get 429s.
#
# In the default regex-only triage mode these only govern the deep tier, which
# is the sole remaining source of LLM calls — the file pool is still used for
# triage, but there it parallelises local regex work, not network round trips.
# Deep-tier nesting (file_workers * chunk_workers, worst case 8*3=24 in-flight
# requests) is what MAX_INFLIGHT_LLM_CALLS actually throttles.
MAX_INFLIGHT_LLM_CALLS = 10
# Small deep-scan files whose system prompt the provider won't cache (below
# the model's cache minimum, or a non-Bedrock provider) are reviewed several
# per call: the prompt is paid once per batch instead of once per file. On a
# repo of small Angular files the prompt was ~90% of every call's input.
BATCH_FILE_MAX_CHARS = 6_000
BATCH_CHAR_BUDGET = 16_000
BATCH_MAX_FILES = 8
DEFAULT_FILE_WORKERS = 8
DEFAULT_CHUNK_WORKERS = 3

# group_confirm_unverified_findings tunables. TRIAGE_CONFIRM_GROUP_CAP bounds
# how many unverified groups get an LLM call per scan (top-N by occurrence
# count) — a backstop against repos with hundreds of groups, independent of
# LLM_COST_CUTOFF_USD. DEFAULT_GROUPS_PER_CALL packs multiple groups into one
# call_llm call so the system prompt/OWASP label overhead is paid once per
# batch instead of once per group.
TRIAGE_CONFIRM_GROUP_CAP = 50
DEFAULT_GROUPS_PER_CALL = 5

# A false_positive-verdict deep-scan finding at or below this confidence (=
# "how sure you are this is exploitable") is a confident self-dismissal by the
# model — suppressed outright when suppress_low_confidence_false_positives is
# on, regardless of rule_id.
FALSE_POSITIVE_SUPPRESS_CONFIDENCE_CEILING = 0.2

# Path-heuristic risk levels that get a full LLM-primary pass (no regex gate).
LLM_RISK_LEVELS = frozenset({"CRITICAL", "HIGH"})
# Levels that are regex-gated instead: zero hits means no LLM call at all, and
# files with hits send only the hit candidates plus their context windows.
TRIAGE_RISK_LEVELS = frozenset({"MEDIUM", "LOW"})

# Every severity an *unverified* (regex-tier) finding can carry. MEDIUM/LOW
# files always land here; CRITICAL/HIGH files past DEEP_SCAN_FILE_CAP are
# routed here too but keep their true risk_level (see scan_deep_files_paths /
# node_map_modules_and_risk), so a group_unverified_findings caller that
# defaults to TRIAGE_RISK_LEVELS alone silently strands those overflow
# findings at verdict=unverified forever.
UNVERIFIED_FINDING_SEVERITIES = LLM_RISK_LEVELS | TRIAGE_RISK_LEVELS

# Top-N CRITICAL/HIGH files (bucket order: CRITICAL first, then HIGH) that get
# the full whole-file deep scan. On a large repo the CRITICAL/HIGH bucket can
# itself run into the hundreds; beyond this cap, files still carrying
# CRITICAL/HIGH risk_level are routed into the regex-gated triage tier instead
# of the whole-file scan — see node_map_modules_and_risk. Overridable per-scan
# via state["deep_scan_file_cap"].
DEEP_SCAN_FILE_CAP = 100

# How the MEDIUM/LOW (+ deep-scan overflow) tier turns regex hits into findings.
#
#   regex_only  — no LLM at all. Every hit is published as-is with
#                 verdict="unverified": nobody has confirmed it, and saying so
#                 is more honest than guessing. This is the default because on
#                 a large repo the per-file triage call was the entire runtime
#                 cost (thousands of round trips), while the regex pass itself
#                 measures ~5ms/file.
#   llm_triage  — the previous behaviour: hits plus their context windows go to
#                 the LLM for a true/false-positive ruling. Kept switchable
#                 rather than deleted; it is strictly more precise, just far
#                 more expensive.
#
# Overridable per-scan via state["triage_mode"].
TRIAGE_MODE_REGEX_ONLY = "regex_only"
TRIAGE_MODE_LLM = "llm_triage"
TRIAGE_MODES = frozenset({TRIAGE_MODE_REGEX_ONLY, TRIAGE_MODE_LLM})
DEFAULT_TRIAGE_MODE = TRIAGE_MODE_REGEX_ONLY

# Reason recorded on a regex-only finding, in place of the model's rationale.
UNVERIFIED_REASON = (
    "Regex pattern match, not reviewed by an LLM — confirm before acting on it."
)

_INFLIGHT = threading.Semaphore(MAX_INFLIGHT_LLM_CALLS)
_CALLBACK_LOCK = threading.Lock()

# Extensions that are never meaningful LLM scan targets even if they slip past
# the directory walk (e.g. tests building bare module_plan dicts).
NON_SOURCE_FILE_EXTS = frozenset({
    ".class", ".jar", ".war", ".ear", ".pyc", ".pyo",
    ".dll", ".so", ".dylib", ".exe", ".bin", ".o", ".a", ".lib", ".wasm",
})

# Schema / IDE / VCS / logging-config noise: still listed in Discovery, never
# LLM-scanned or regex-scanned for findings. Walk skip lists are unchanged —
# Maven target/ is walk-excluded; do not treat "target" as a path segment here
# (that would skip a Java package named target).
SKIP_FINDING_SCAN_EXTS = frozenset({
    ".xsd", ".wsdl", ".dtd", ".compose", ".parse",
    ".library", ".prefs", ".project", ".classpath",
    ".jpx", ".jbx", ".jsdtscope",
    ".map", ".gz", ".crt", ".pid", ".csv", ".mf", ".name",
    ".sh",
})
SKIP_FINDING_SCAN_FILENAMES = frozenset({
    "log4j.xml", "log4j2.xml", "log4j.dtd",
    "manifest.mf",
    ".cvsignore", ".project", ".classpath", ".jsdtscope", ".prefs",
})
SKIP_FINDING_SCAN_DIR_SEGMENTS = frozenset({
    "cvs", "xsd",
    "node_modules", ".settings", ".idea",
})
# config/ and configuration/ directories hold legacy XML/data noise, but also
# Java packages (com/acme/config/SecurityConfig.java — where Spring Security
# rules usually live) and Spring Boot's own config/application.yml. Only the
# data files there are excluded; see config_dir_file_is_scannable.
CONFIG_DIR_SEGMENTS = frozenset({"config", "configuration"})
_CONFIG_DIR_SOURCE_EXTS = frozenset({
    ".java", ".kt", ".kts", ".groovy", ".scala",
    ".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
    ".cs", ".go", ".rb", ".php", ".rs", ".swift",
})
# Runtime configuration that can embed secrets — the same Spring Boot naming
# convention the maven-java risk profile flags CRITICAL, plus .env files.
_CONFIG_DIR_RUNTIME_RE = re.compile(
    r"^(?:application|bootstrap)(?:-[\w.]+)?\.(?:properties|ya?ml)$|^\.env(?:\..*)?$",
    re.IGNORECASE,
)


def config_dir_file_is_scannable(filename: str) -> bool:
    """True for a file inside a config/ or configuration/ directory that is
    source code or secret-bearing runtime config, not legacy data noise."""
    name = Path(filename).name
    return Path(name).suffix.lower() in _CONFIG_DIR_SOURCE_EXTS or bool(_CONFIG_DIR_RUNTIME_RE.match(name))


def in_config_dir(rel_path: str) -> bool:
    parts = Path(str(rel_path).replace("\\", "/")).parts[:-1]
    return any(part.lower() in CONFIG_DIR_SEGMENTS for part in parts)
SKIP_FINDING_SCAN_LOG4J_EXTS = frozenset({".xml", ".dtd"})

_JAVA_CLASS_MAGIC = b"\xca\xfe\xba\xbe"

# Meta-findings the model emits when shown bytecode/minified gibberish.
_UNANALYZABLE_META_RE = re.compile(
    r"(?i)"
    r"(?:cannot be (?:reliably )?analyzed|cannot be reliably reviewed|"
    r"does not represent actual source|bytecode file|compiled .{0,40}bytecode|"
    r"original .{0,40}source code .{0,40}required|"
    r"no concrete .{0,60}(?:can be )?identified|"
    r"unreadable format|garbled characters)"
)

_RESULTSET_READ_RE = re.compile(
    r"\b(?:rs|resultSet|result_set)\s*\.\s*get(?:String|Int|Long|Object|BigDecimal|Date)\s*\(",
    re.IGNORECASE,
)
_SQL_BUILD_RE = re.compile(
    r"\b(?:SELECT|INSERT|UPDATE|DELETE|MERGE)\b.*?(?:\+|\|\||\.format\s*\(|String\.format|%s|\$\{|f\")",
    re.IGNORECASE | re.DOTALL,
)
_LOGGING_CALL_RE = re.compile(
    r"\b(?:console\.log|(?:this\.)?logger\.(?:log|trace|debug|info|warn|error|fatal))\s*\(",
    re.IGNORECASE,
)

# CWEs the LLM tends to use for "plaintext/cleartext HTTP instead of HTTPS"
# findings, plus a title/reason keyword fallback for findings that describe
# the issue without naming one of these CWEs. Deliberately narrow (requires
# an explicit HTTP-vs-HTTPS/cleartext phrase, not a bare "http" substring) so
# an unrelated "HTTP 500 error" finding is never caught by this.
_HTTP_FINDING_CWES = frozenset({"CWE-319", "CWE-311", "CWE-523", "CWE-757"})
_HTTP_FINDING_RE = re.compile(
    r"(?i)\b(?:cleartext|plaintext)\b.{0,30}\b(?:http|transmission|transport)\b"
    r"|\bhttp\b(?!s)[^.]{0,40}\b(?:instead of|not|without)\b[^.]{0,20}\bhttps\b"
    r"|\b(?:missing|no|not enforc\w*|disabled)\b[^.]{0,20}\bhttps\b"
    r"|\bunencrypted\b.{0,20}\b(?:http|transport|traffic|connection)\b"
)


def _is_http_related_finding(finding: Dict[str, Any]) -> bool:
    """True when a finding is about cleartext HTTP / missing HTTPS enforcement
    — used only when a project has told us (via the https-enforced-suppress-http
    scan limitation) that HTTPS is enforced at a layer the scan can't see."""
    cwe = (finding.get("cwe") or "").strip().upper()
    if cwe in _HTTP_FINDING_CWES:
        return True
    blob = " ".join([finding.get("title") or "", finding.get("verdict_reason") or ""])
    return bool(_HTTP_FINDING_RE.search(blob))

# Lines worth hoisting into the skeleton: where untrusted data enters.
_TAINT_SOURCE_RE = re.compile(
    r"""(?xi)
    (?:
        \bget(?:Parameter|ParameterValues|Header|QueryString|Cookies|PathInfo|InputStream|Reader)\s*\(
      | @(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|ModelAttribute)\b
      | \breq(?:uest)?\s*\.\s*(?:body|query|params|headers|cookies)\b
      | \brequest\.(?:GET|POST|args|form|json|values|data)\b
      | \bprocess\.argv\b
      | \bsys\.argv\b
      | \bos\.environ\b
      | \bSystem\.getenv\s*\(
      | \binput\s*\(
      | \bScanner\s*\(
    )
    """
)

# Lines worth hoisting into the skeleton: where data leaves into an interpreter.
_TAINT_SINK_RE = re.compile(
    r"""(?xi)
    (?:
        \bexecute(?:Query|Update|Batch|LargeUpdate)?\s*\(
      | \bcreateStatement\s*\(
      | \bprepareStatement\s*\(
      | \bcreate(?:Native)?Query\s*\(
      | \bjdbcTemplate\s*\.
      | \bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(
      | \bProcessBuilder\s*\(
      | \bchild_process\b
      | \bsubprocess\b
      | \bos\.system\s*\(
      | \bpopen\s*\(
      | \beval\s*\(
      | \bexec\s*\(
      | \binnerHTML\b
      | \bdangerouslySetInnerHTML\b
      | \bdocument\.write\s*\(
      | \bObjectInputStream\s*\(
      | \breadObject\s*\(
      | \bXPath(?:Factory|Expression)?\b
      | \bDirContext\b
      | \bnew\s+File\s*\(
      | \bFileInputStream\s*\(
      | \bRestTemplate\b | \bWebClient\b | \bHttpClient\b | \brequests\.(?:get|post)\s*\(
    )
    """
)

_IMPORT_RE = re.compile(r"^\s*(?:package|import|from|using|#include|require\s*\()")

_EXT_TO_LANG: Dict[str, str] = {
    ".java": "java",
    ".kt": "java",
    ".jsp": "java",
    ".ts": "typescript", ".tsx": "typescript",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    # Single-file components: script and template share the JS rule set, and
    # the template rules (rules/frontend-templates.json) list javascript too.
    ".vue": "javascript", ".svelte": "javascript",
    ".py": "python",
    ".go": "go",
    ".cs": "csharp",
    ".php": "php",
    ".rb": "ruby",
    ".xml": "xml",
    ".properties": "properties",
    ".yml": "yaml", ".yaml": "yaml",
    ".env": "env",
    ".html": "html",
    ".sql": "sql",
    ".sh": "shell",
    ".tf": "terraform",
}

# Heuristic top-level declaration starts, used to snap a chunk cut to a clean
# boundary rather than mid-function, and to pick signature lines for the
# skeleton — not a parser, just a nicer split point for a line-window chunker.
_BOUNDARY_PATTERNS: Dict[str, re.Pattern] = {
    "java": re.compile(r"^\s*(public|private|protected|static|final|abstract|@\w+)\b"),
    "typescript": re.compile(r"^\s*(export|public|private|protected|static|async|function|class|interface)\b"),
    "javascript": re.compile(r"^\s*(export|function|class|async|const\s+\w+\s*=\s*(?:async\s*)?\()"),
    "python": re.compile(r"^\s*(def |class |async def )"),
    "go": re.compile(r"^\s*(func|type)\b"),
    "csharp": re.compile(r"^\s*(public|private|protected|internal|static|async|class|interface)\b"),
    "php": re.compile(r"^\s*(function|class|public|private|protected)\b"),
    "ruby": re.compile(r"^\s*(def |class |module )"),
}


_GITHUB_WORKFLOW_RE = re.compile(r"(^|/)\.github/workflows/[^/]+$")


def lang_for_path(path: str) -> Optional[str]:
    """Extension -> rule-catalog language tag (for catalog filtering and
    chunk-boundary heuristics). None for unrecognized extensions — such files
    still get scanned, just with the universal (untagged) rule subset."""
    posix = path.replace("\\", "/")
    name = posix.rsplit("/", 1)[-1].lower()
    # Extension-less / name-keyed files: the rule vocabulary needs a tag for
    # them or only the untagged rules would ever see them.
    if name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile"):
        return "dockerfile"
    suffix = Path(path).suffix.lower()
    if suffix in (".yml", ".yaml") and _GITHUB_WORKFLOW_RE.search(posix):
        return "github-actions"
    return _EXT_TO_LANG.get(suffix)


# --- chunking ---------------------------------------------------------------

def chunk_file(text: str, lang: Optional[str]) -> List[Dict[str, Any]]:
    """Size check -> single chunk, or method/function-boundary line-window
    chunks with an overlap generous enough that a source/sink pair straddling
    a cut usually survives in at least one chunk."""
    lines = text.splitlines()
    if not lines:
        return []
    if len(text) <= SINGLE_CALL_CHAR_BUDGET:
        return [{"start_line": 1, "end_line": len(lines), "text": text}]

    boundary_re = _BOUNDARY_PATTERNS.get(lang or "")
    chunks: List[Dict[str, Any]] = []
    n = len(lines)
    start = 0
    while start < n:
        end = min(start + CHUNK_LINE_BUDGET, n)
        if end < n and boundary_re is not None:
            for probe in range(end, min(end + 60, n)):
                if boundary_re.match(lines[probe]):
                    end = probe
                    break
        chunks.append({
            "start_line": start + 1,
            "end_line": end,
            "text": "\n".join(lines[start:end]),
        })
        if end >= n:
            break
        start = max(end - OVERLAP_LINES, start + 1)
    return chunks


def build_file_skeleton_entries(
    text: str, lang: Optional[str], *, max_lines: int = SKELETON_MAX_LINES,
) -> List[Tuple[int, str, str]]:
    """(line, kind, text) for imports, declarations, and every line that looks
    like an untrusted-input source or a dangerous sink. kind is one of
    "taint", "import", "decl"."""
    lines = text.splitlines()
    decl_re = _BOUNDARY_PATTERNS.get(lang or "")
    picked: List[Tuple[int, str, str]] = []
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        kind = ""
        if i <= 60 and _IMPORT_RE.match(line):
            kind = "import"
        elif _TAINT_SOURCE_RE.search(line) or _TAINT_SINK_RE.search(line):
            kind = "taint"
        elif decl_re is not None and decl_re.match(line) and (
            "(" in stripped or " class " in f" {stripped} " or "interface" in stripped
        ):
            kind = "decl"
        if kind:
            picked.append((i, kind, stripped[:SKELETON_LINE_MAX_CHARS]))
            if len(picked) >= max_lines:
                break
    return picked


_SKELETON_KIND_PRIORITY = {"taint": 0, "import": 1, "decl": 2}


def skeleton_for_chunk(
    entries: Sequence[Tuple[int, str, str]],
    start_line: int,
    end_line: int,
    *,
    max_chars: int = SKELETON_CHUNK_MAX_CHARS,
) -> str:
    """The skeleton as seen from one chunk: entries inside [start_line,
    end_line] are dropped (the chunk already shows them), and if the rest
    exceeds `max_chars`, taint lines are kept before imports and declarations.
    Output stays in file order."""
    outside = [e for e in entries if not (start_line <= e[0] <= end_line)]
    budget = max_chars
    chosen: List[Tuple[int, str, str]] = []
    truncated = False
    for entry in sorted(outside, key=lambda e: (_SKELETON_KIND_PRIORITY.get(e[1], 9), e[0])):
        cost = len(entry[2]) + 8
        if cost > budget:
            truncated = True
            continue
        budget -= cost
        chosen.append(entry)
    out = [f"{line}: {text}" for line, _kind, text in sorted(chosen)]
    if truncated:
        out.append("… (skeleton truncated)")
    return "\n".join(out)


def build_file_skeleton(text: str, lang: Optional[str], *, max_lines: int = SKELETON_MAX_LINES) -> str:
    """A compact whole-file map: imports, declarations, and every line that
    looks like an untrusted-input source or a dangerous sink.

    This is the main recall fix for chunked files. Without it, a chunk holding
    `stmt.executeQuery(sql)` has no way to know `sql` was built from
    `request.getParameter("id")` 300 lines earlier, and the model correctly but
    uselessly reports "cannot determine if input is trusted"."""
    entries = build_file_skeleton_entries(text, lang, max_lines=max_lines)
    out = [f"{line}: {stripped}" for line, _kind, stripped in entries]
    if len(entries) >= max_lines:
        out.append("… (skeleton truncated)")
    return "\n".join(out)


_LICENSE_RE = re.compile(r"licen[cs]e|copyright|\(c\)", re.IGNORECASE)
_HASH_COMMENT_RE = re.compile(r"^\s*#(?:\s|$)")


def leading_license_header_span(lines: Sequence[str]) -> Optional[Tuple[int, int]]:
    """1-based (first, last) lines of a leading license/copyright comment
    block, or None.

    Recognises a /* ... */ or <!-- ... --> block, or a run of `//` or `# `
    line comments (blank lines and a shebang/coding line before it are
    skipped, and stay in the prompt). Only blocks of at least
    LICENSE_HEADER_MIN_LINES lines that actually mention a license or
    copyright qualify — any other leading comment may carry security-relevant
    notes and is sent as-is."""
    i = 0
    n = len(lines)
    while i < n:
        stripped = lines[i].strip()
        if not stripped or stripped.startswith("#!") or (
            stripped.startswith("#") and "coding" in stripped[:40]
        ):
            i += 1
            continue
        break
    if i >= n:
        return None
    first = lines[i].lstrip()
    end = -1
    if first.startswith("/*") or first.startswith("<!--"):
        closer = "*/" if first.startswith("/*") else "-->"
        for j in range(i, n):
            if closer in lines[j]:
                if lines[j].split(closer, 1)[1].strip():
                    return None  # code shares the closing line; leave it alone
                end = j
                break
    elif first.startswith("//") or _HASH_COMMENT_RE.match(first):
        j = i
        while j < n and (
            lines[j].lstrip().startswith("//") if first.startswith("//")
            else _HASH_COMMENT_RE.match(lines[j])
        ):
            j += 1
        end = j - 1
    if end < 0 or end - i + 1 < LICENSE_HEADER_MIN_LINES:
        return None
    if not _LICENSE_RE.search("\n".join(lines[i:end + 1])):
        return None
    return i + 1, end + 1


def _read_text(repo_root: Path, rel_path: str) -> Optional[str]:
    try:
        return (repo_root / rel_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


# Test code by directory *and* by file name: legacy Java repos keep
# *Test.java / *TestClient.java beside production code under src/main, and
# frontend tests sit next to the component they test. Matched against the
# POSIX relative path.
_TEST_DIR_RE = re.compile(
    r"(?:^|/)(?:src/test|src/it|test|tests|__tests__|__mocks__|e2e|cypress|spec|specs)/",
    re.IGNORECASE,
)
_TEST_FILE_RE = re.compile(
    r"(?:"
    r"\w*(?:Test|Tests|TestCase)\d*\.(?:java|kt|scala)"
    r"|\w*[a-z0-9](?:IT|ITCase)\.(?:java|kt)"
    r"|\w*TestClient\w*\.(?:java|kt)"
    r"|[\w.-]+\.(?:spec|test|e2e-spec|cy)\.[cm]?[jt]sx?"
    r"|test_\w+\.py|\w+_test\.(?:py|go)|conftest\.py"
    r")$"
)


def is_test_path(rel_path: str) -> bool:
    """True for test code: a test directory anywhere in the path, or a test
    file-name convention (FooTest.java, FooIT.java, FooTestClient.java,
    foo.spec.ts, foo.test.js, test_foo.py, foo_test.go)."""
    posix = str(rel_path or "").replace("\\", "/").lstrip("/")
    if _TEST_DIR_RE.search(posix):
        return True
    return bool(_TEST_FILE_RE.search(posix.rsplit("/", 1)[-1]))


def is_non_source_path(rel_path: str) -> bool:
    return Path(rel_path).suffix.lower() in NON_SOURCE_FILE_EXTS


def is_excluded_from_finding_scan(rel_path: str) -> bool:
    """True for schema, IDE, CVS, log4j config and shell-script paths, and
    for data files (not source code or runtime config) under config/ or
    configuration/.

    These remain in Discovery; they are not queued for LLM or regex findings.
    """
    path = Path(str(rel_path).replace("\\", "/"))
    suffix = path.suffix.lower()
    name = path.name.lower()
    if suffix in SKIP_FINDING_SCAN_EXTS:
        return True
    if name in SKIP_FINDING_SCAN_FILENAMES:
        return True
    if "log4j" in name and suffix in SKIP_FINDING_SCAN_LOG4J_EXTS:
        return True
    if in_config_dir(str(path)) and not config_dir_file_is_scannable(name):
        return True
    return any(
        segment.lower() in SKIP_FINDING_SCAN_DIR_SEGMENTS
        for segment in path.parts[:-1]
    )


def looks_like_binary_content(text: str, *, sample_chars: int = 8000) -> bool:
    """Heuristic for UTF-8-misread binary (nulls, replacement chars, control bytes)."""
    if not text:
        return False
    sample = text[:sample_chars]
    if not sample:
        return False
    bad = 0
    for ch in sample:
        code = ord(ch)
        if ch == "\ufffd" or code == 0 or (code < 32 and ch not in "\t\n\r"):
            bad += 1
    return (bad / len(sample)) > 0.05


def _read_head_bytes(repo_root: Path, rel_path: str, n: int = 512) -> Optional[bytes]:
    try:
        with (repo_root / rel_path).open("rb") as fh:
            return fh.read(n)
    except OSError:
        return None


# Machine-generated source (Castor/JAXB bindings, wsdl2java stubs, protobuf,
# ORM models). Findings in it are not actionable — you would fix the schema or
# the generator, never the output — and a legacy repo can carry thousands of
# such files, all near-identical, which is pure report noise.
#
# Detected by content marker rather than by path: generated code lives in
# wildly different directories per generator, while the header convention is
# near-universal. Path matching would also wrongly skip a hand-written package
# that merely happens to be called `gen/`.
_GENERATED_MARKERS = re.compile(
    r"(?i)("
    r"@Generated\b"
    r"|DO NOT EDIT"
    r"|do not modify this file"
    r"|automatically generated"
    r"|auto-?generated"
    r"|generated by "
    r"|this (?:class|file) was generated"
    r"|generated from .{0,40}\.(?:xsd|wsdl|proto)"
    r")"
)
# Only the header is inspected: a marker this far in is a comment about
# generation, not a declaration that this file is generated.
GENERATED_HEADER_SCAN_CHARS = 4000


def looks_generated(text: Optional[str]) -> bool:
    """True when the file's header marks it as machine-generated."""
    if not text:
        return False
    return bool(_GENERATED_MARKERS.search(text[:GENERATED_HEADER_SCAN_CHARS]))


# Vendored/minified third-party libraries (jQuery, Bootstrap, bootstrap-select,
# dropzone, ...). Findings inside them are not actionable — nobody fixes a
# vendored dependency's own minified source — and regex rules written for
# hand-authored code (DOM XSS via innerHTML, non-literal RegExp) fire
# constantly on library internals.
#
# Detected by filename convention and content shape rather than by directory
# path: vendor code lives under wildly different directory names per project
# (assets/libraries, vendor, lib, third-party, ...), while ".min.js"/".min.css"
# is a near-universal minifier output convention, and minified code is
# characteristically very-long-lines regardless of where it lives. Path
# matching would also wrongly skip a hand-written package that merely happens
# to live under a dir named "lib".
_MINIFIED_FILENAME_SUFFIXES = (".min.js", ".min.css")
_MINIFIED_MIN_CONTENT_CHARS = 2000
_MINIFIED_AVG_LINE_LENGTH_THRESHOLD = 300


def looks_vendored_or_minified(rel_path: str, text: Optional[str]) -> bool:
    """True when the file is a minified/vendored third-party asset."""
    if Path(rel_path).name.lower().endswith(_MINIFIED_FILENAME_SUFFIXES):
        return True
    if not text or len(text) < _MINIFIED_MIN_CONTENT_CHARS:
        return False
    line_count = text.count("\n") + 1
    avg_line_length = len(text) / line_count
    return avg_line_length > _MINIFIED_AVG_LINE_LENGTH_THRESHOLD


# Files that only declare shapes — nothing executes, so there is no source,
# sink or missing check for a reviewer to find. Detected by content, like
# looks_generated, and deliberately narrow: anything that could hold logic,
# a query string or a value disqualifies the file.
#
# Spring Data repository interface: derived query methods (findByEmail) are
# built by the framework from the method name and bound as parameters. An
# @Query/native query is a string someone wrote, and @RepositoryRestResource
# exposes the repository over HTTP — either keeps the file in.
_SPRING_DATA_REPO_RE = re.compile(
    r"\binterface\s+\w+(?:<[^>{]*>)?\s+extends\s+[^{]*?\b\w*Repository\s*<"
)
_SPRING_DATA_DISQUALIFIERS = re.compile(
    r"@(?:Query|NativeQuery|Procedure|RepositoryRestResource|RestResource)\b"
    r"|\b(?:default|static)\s+[\w<>\[\],\s]+\s+\w+\s*\("
    r"|\b(?:class|enum|record)\s+\w+"
)
_TS_DECLARATION_SUFFIXES = (".ts", ".mts", ".cts")
_TS_COMMENT_RE = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)
# Statements allowed at brace depth 0 of a type-only TypeScript file.
_TS_DECLARATION_LINE_RE = re.compile(
    r"^(?:"
    r"import\b"
    r"|export\s+(?:\{|\*|type\s*\{)"
    r"|(?:export\s+)?(?:declare\s+)?(?:interface|type|enum|const\s+enum)\s+\w"
    r"|export\s+default\s+interface\b"
    r"|[}|&]"
    r")"
)


def looks_declaration_only(rel_path: str, text: Optional[str]) -> bool:
    """True for a Spring Data repository interface with derived queries only,
    or a TypeScript file holding only imports and interface/type/enum
    declarations."""
    if not text:
        return False
    lower = rel_path.lower()
    if lower.endswith(".java"):
        return bool(_SPRING_DATA_REPO_RE.search(text)) and not _SPRING_DATA_DISQUALIFIERS.search(text)
    if not lower.endswith(_TS_DECLARATION_SUFFIXES):
        return False
    depth = 0
    declarations = 0
    for raw in _TS_COMMENT_RE.sub("", text).splitlines():
        line = raw.strip()
        if not line:
            continue
        if depth == 0:
            if not _TS_DECLARATION_LINE_RE.match(line):
                return False
            if not line.startswith(("import", "}", "|", "&")):
                declarations += 1
        depth += line.count("{") - line.count("}")
        if depth < 0:
            return False
    return declarations > 0 and depth == 0


def is_non_analyzable_file(repo_root: Path, rel_path: str, text: Optional[str] = None) -> Optional[str]:
    """Return a skip reason when the file cannot be source-reviewed, else None."""
    if is_excluded_from_finding_scan(rel_path):
        return "schema, CVS, configuration directory, or log4j config"
    if is_non_source_path(rel_path):
        return f"non-source extension {Path(rel_path).suffix.lower()}"
    head = _read_head_bytes(repo_root, rel_path)
    if head is not None and head.startswith(_JAVA_CLASS_MAGIC):
        return "java class bytecode"
    if head is not None and b"\x00" in head:
        return "binary null bytes"
    if text is not None and looks_like_binary_content(text):
        return "binary or non-text content"
    if text is not None and looks_generated(text):
        return "machine-generated source"
    if looks_vendored_or_minified(rel_path, text):
        return "vendored/minified third-party code"
    if looks_declaration_only(rel_path, text):
        return "declarations only (nothing that executes)"
    return None


# --- prompt -----------------------------------------------------------------

_SYSTEM_HEAD = (
    "You are a senior application security engineer performing manual source-code "
    "review. You are shown one code chunk from a high-risk file, a skeleton map "
    "of the rest of the file, a catalog of known vulnerability patterns as guidance "
    "(not a checklist to match verbatim), and the project's tech-stack context.\n\n"
    "Your job is to find real, concrete security issues — especially where untrusted "
    "input reaches SQL, OS commands, LDAP, XPath, deserialization, file paths, "
    "template engines, the DOM, an HTTP response body (reflected/stored XSS — this "
    "includes a Java/Spring backend echoing an exception message, validation error, a "
    "raw @RequestParam/@PathVariable value, or other user-controlled text back into a "
    "ResponseEntity/response writer without encoding — whether it is written directly, "
    "first assigned to a local variable, wrapped in a DTO/Map before being returned "
    "(this applies equally to new ResponseEntity<>(dto, status) and to the "
    ".body()/.ok() fluent form — they are the same sink), or accumulated into a "
    "StringBuilder/list across a loop over multiple validation errors before being "
    "returned — the accumulation does not launder the taint), or a log statement (log "
    "injection/forging — unsanitized newlines or control characters from user input "
    "reaching a logger call, including when the logged value is an exception message, "
    "a request accessor like getRequestURI()/getQueryString() (not just "
    "getParameter()/getHeader()), or was first assigned to a variable — and "
    "regardless of which argument position it appears in when the call takes several "
    "parameterized arguments). Also flag CSRF protection that is disabled or missing "
    "on state-changing, session-authenticated endpoints, and an unchecked "
    "decrement/subtraction feeding an array index, loop bound, allocation size, or "
    "buffer/count field without a prior bounds check (integer underflow, "
    "CWE-191).\n\n"
    "How to reason:\n"
    "- Trace data flow. Name the untrusted SOURCE and the dangerous SINK. If the "
    "source is not in the chunk, check the skeleton map — it lists every input "
    "source and sink line in the whole file with line numbers.\n"
    "- A sink fed only by literals, constants, enums, or values the code itself "
    "produced is not a vulnerability.\n"
    "- Parameterised queries (bound `?` / named parameters) are safe even when the "
    "surrounding code concatenates non-parameter fragments.\n"
    "- A value passed to a `PreparedStatement` setter is data, not SQL text.\n"
    "- Do NOT flag JDBC ResultSet getters (rs.getString, getInt, etc.) as SQL "
    "injection; reading a column from a query result is not building SQL.\n"
    "- Do NOT flag string concatenation that does not build a query, command, path, "
    "or markup.\n"
    "- A log statement can raise two separate questions: log forging (CWE-117 — a "
    "value that can carry a line break reaches a log) and sensitive data written to "
    "a log (CWE-532 — a credential, token or personal data in any logger or "
    "System.out/System.err line, at any log level). Decide each on its own; "
    "neither answer dismisses the other.\n"
    "- Parameterised logging (`{}` placeholders), a Throwable argument and "
    "structured fields are NOT defences against log forging: the message and the "
    "stack trace are written unchanged. Only the log layout or explicit encoding "
    "neutralises line breaks.\n"
    "- System.out/System.err is a disclosure sink (CWE-532) but never an XSS sink: "
    "cross-site scripting needs a value written to an HTTP response or a JSP "
    "writer.\n"
    "- For an Angular translation lookup or a component property, follow the value "
    "to where its template renders it: `{{ }}` interpolation and text bindings are "
    "escaped; `[innerHTML]` after bypassSecurityTrust*, a native element write or "
    "eval/new Function are the dangerous contexts. A dictionary lookup alone is "
    "never code execution.\n"
    "- When a file configures how an incoming bearer token (JWT/OIDC/OAuth access or "
    "ID token) is validated — NimbusJwtDecoder, JwtDecoders, oauth2ResourceServer, a "
    "jjwt/auth0/nimbus parser, jsonwebtoken.verify, passport-jwt — check that the "
    "validation covers the signature, the expiry, the issuer (iss) AND the audience "
    "(aud). A decoder built only from a JWK set URI or a shared secret checks the "
    "signature (and usually expiry) alone, so a token minted for a different "
    "tenant, project or client by the same identity provider is accepted. Report "
    "that as missing token validation (CWE-345, A07) and name which of iss/aud is "
    "unchecked. An issuer-location helper validates the issuer but not the "
    "audience. Do not report it when a validator for each is visibly configured.\n"
    "- For a Dockerfile, CI workflow or cloud template, the findings are often an "
    "ABSENCE: a Dockerfile with no USER instruction (runs as root); a GitHub Actions "
    "workflow with no `permissions:` block or with third-party actions pinned to a "
    "tag instead of a commit SHA; a database or bucket resource with no encryption "
    "property, no deletion/backup setting, or reachable from 0.0.0.0/0. Read the "
    "whole file before deciding something is absent.\n"
    "- When checking for a MISSING security feature (an attribute, header, token, "
    "config setting, etc.) on a specific element (a specific input field, endpoint, "
    "class, or config block), re-read that exact element's own declaration/line(s) "
    "in full before deciding it is absent — attributes are frequently split across "
    "multiple lines or wrapped, and a quick skim misses them. Do not infer that one "
    "element has the feature because a *different* element elsewhere in the file has "
    "it (e.g. one input field having autocomplete set does not mean another field "
    "does). Only report 'missing' after confirming that specific element's own "
    "declaration truly lacks it. If you misread it and it is actually present on "
    "that element, mark as false_positive and say so in verdict_reason. Global "
    "features that apply file-wide or app-wide (e.g. a CSRF filter configured once "
    "for the whole app) are the one case where checking the skeleton/whole file for "
    "any configuration of that feature is the right scope.\n"
    "- Use the catalog to calibrate severity/CWE/OWASP vocabulary, but do not limit "
    "yourself to it — flag anything else that is a genuine vulnerability.\n"
    "- Report the line number exactly as shown in the numbered code. Never invent a "
    "line number, and never report a line outside the chunk shown.\n"
    "- For every candidate issue decide true_positive or false_positive and always "
    "give a verdict_reason, even for false positives.\n"
    "- If the file is not human-readable source code (bytecode, compiled binary, "
    "garbled decompiler output, etc.), return no findings — do not emit a finding "
    "about being unable to analyze.\n\n"
    "Respond with the JSON object described under Output format only. No prose, "
    "no markdown fences."
)


def render_catalog(catalog: Sequence[Dict[str, Any]]) -> str:
    """One line per rule: `- id | CWE | SEVERITY | title: description`.

    Replaces an indented JSON dump of the same entries (~2x the characters for
    the same content). OWASP labels are deliberately not repeated per rule —
    findings that cite a catalog id get the rule's label filled in locally
    (see `catalog_owasp_index`)."""
    out = []
    for rule in catalog:
        title = str(rule.get("title") or "").strip()
        desc = str(rule.get("description") or "").strip()
        text = f"{title}: {desc}" if desc and desc != title else title
        out.append(
            f"- {rule.get('id')} | {rule.get('cwe') or '-'} | "
            f"{rule.get('severity') or '-'} | {text}"
        )
    return "\n".join(out)


def catalog_owasp_index(catalog: Sequence[Dict[str, Any]]) -> Dict[str, str]:
    return {
        str(rule["id"]): str(rule["owasp"])
        for rule in catalog
        if rule.get("id") and rule.get("owasp") in OWASP_TOP_10_2021
    }


def catalog_rule_index(catalog: Sequence[Dict[str, Any]]) -> Dict[str, Dict[str, str]]:
    """Catalog id -> the title/cwe/owasp a deep-scan finding citing that id may
    leave out of its response (see `_RESPONSE_SCHEMA` field rules); filled back
    in by `normalize_finding`."""
    owasp = catalog_owasp_index(catalog)
    index: Dict[str, Dict[str, str]] = {}
    for rule in catalog:
        rule_id = str(rule.get("id") or "")
        if not rule_id:
            continue
        index[rule_id] = {
            "title": str(rule.get("title") or "").strip(),
            "cwe": str(rule.get("cwe") or "").strip(),
            "owasp": owasp.get(rule_id, ""),
            "issue_class": str(rule.get("issue_class") or "").strip(),
        }
    return index


_RESPONSE_SCHEMA = """Output format — one JSON object:
{"findings": [
  {
    "verdict": "true_positive" | "false_positive",
    "rule_id": "<catalog id if one matches, else \"llm-extra\">",
    "line": <line number from the numbered code>,
    "snippet": "<the flagged line, copied verbatim — that one line only>",
    "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
    "confidence": <0.0-1.0, how sure you are this is exploitable>,
    "verdict_reason": "<required, even for false_positive; at most 2 sentences>",
    "title": "short title",
    "cwe": "CWE-XXX",
    "owasp_category": "<OWASP Top 10:2021 label>",
    "source": "<the untrusted input expression, or \"\" if none identified>",
    "sink": "<the dangerous call this reaches>",
    "data_flow": "<one line: how source reaches sink, naming intermediate variables>",
    "ai_fix": "<at most 2 sentences>"
  }
]}
Field rules — leave a field out rather than repeating what is already known:
- title, cwe, owasp_category: required when rule_id is "llm-extra". Omit them when
  rule_id is a catalog id (they are filled from the catalog), unless the catalog
  CWE does not fit this issue — then give the right cwe.
- source, sink, data_flow, ai_fix: true_positive only. Omit them for false_positive.
If there are no issues, return {"findings": []}."""


def build_system_prompt(
    catalog: List[Dict[str, Any]],
    stack_context: str,
    owasp_labels: Sequence[str] = OWASP_TOP_10_2021,
) -> str:
    """Stable-per-(language, stack) prefix: instructions, output format and the
    catalog. Everything static lives here, ahead of any per-chunk content, so
    the provider prompt cache (llm_client.should_cache_system_prompt) can
    reuse it across every chunk and file."""
    return (
        f"{_SYSTEM_HEAD}\n\n"
        f"{_RESPONSE_SCHEMA}\n\n"
        f"Tech stack: {stack_context or 'unknown'}\n"
        f"OWASP Top 10:2021 categories: {', '.join(owasp_labels)}\n\n"
        "Known vulnerability pattern catalog (guidance only — not exhaustive, not a gate). "
        "Format: id | CWE | severity | title: description\n"
        f"{render_catalog(catalog)}"
    )


def build_user_prompt(
    *,
    file_path: str,
    chunk_text: str,
    start_line: int,
    skeleton: str = "",
    omit_span: Optional[Tuple[int, int]] = None,
) -> str:
    """Per-chunk content only. `omit_span` (1-based, inclusive) collapses those
    lines — a license header — into a single marker line while every other
    line keeps its true number."""
    lines = chunk_text.splitlines()
    numbered: List[str] = []
    for i, line in enumerate(lines):
        number = start_line + i
        if omit_span and omit_span[0] <= number <= omit_span[1]:
            if number == omit_span[0] or number == start_line:
                numbered.append(f"{number}-{omit_span[1]}: [license header omitted]")
            continue
        numbered.append(f"{number}: {line}")
    skeleton_block = (
        "File skeleton (imports, declarations, and every input source / dangerous "
        "sink line elsewhere in the file — use it to trace flows that start outside "
        "this chunk; do not report findings on lines not shown in the code below):\n"
        f"```\n{skeleton}\n```\n\n"
        if skeleton else ""
    )
    return (
        f"File: {file_path}\n\n"
        f"{skeleton_block}"
        f"Code under review (lines {start_line}-{start_line + max(len(lines) - 1, 0)}):\n"
        "```\n" + "\n".join(numbered) + "\n```\n"
    )


def build_batch_user_prompt(files: Sequence[Tuple[str, str, Optional[Tuple[int, int]]]]) -> str:
    """Several complete small files in one prompt: (path, text, license span)
    each. Findings are routed back by the "file" field."""
    blocks = [
        build_user_prompt(file_path=path, chunk_text=text, start_line=1, omit_span=omit_span)
        for path, text, omit_span in files
    ]
    return (
        f"{len(files)} complete files are under review. Judge each file on its own. "
        'Every finding must also carry "file": the path exactly as written after '
        '"File:" for the file it is in.\n\n'
        + "\n".join(blocks)
    )


def build_prompt(
    *,
    file_path: str,
    chunk_text: str,
    start_line: int,
    catalog: List[Dict[str, Any]],
    stack_context: str,
    owasp_labels: Sequence[str] = OWASP_TOP_10_2021,
    skeleton: str = "",
) -> Tuple[str, str]:
    """Back-compatible (system, user) pair."""
    return (
        build_system_prompt(catalog, stack_context, owasp_labels),
        build_user_prompt(
            file_path=file_path, chunk_text=chunk_text,
            start_line=start_line, skeleton=skeleton,
        ),
    )


# Kept for callers that imported it.
SYSTEM_PROMPT = _SYSTEM_HEAD


def trim_catalog(catalog: List[Dict[str, Any]], *, drop_patterns_over: int = 60) -> List[Dict[str, Any]]:
    """Keep only the fields the model actually needs. On very large catalogs the
    `pattern` field is dropped — at that size the regexes cost more tokens and
    attention than they buy in calibration."""
    keep_pattern = len(catalog) <= drop_patterns_over
    fields = ("id", "title", "description", "cwe", "severity", "owasp", "issue_class") + (
        ("pattern",) if keep_pattern else ()
    )
    return [{k: rule[k] for k in fields if k in rule} for rule in catalog]


# --- normalization / anchoring / dedupe -------------------------------------

# "unverified" is what regex-only triage records (and what an unusable LLM
# answer becomes, see parse_verdict); it must stay a recognised verdict so
# nothing downstream rewrites it to false_positive.
VERDICT_UNVERIFIED = "unverified"
_VALID_VERDICTS = {"true_positive", "false_positive", VERDICT_UNVERIFIED}

# The decision contract. `app/models.py` holds the same sets (the engine cannot
# import `app`); tests/test_verdict_contract.py fails if the copies drift.
VERDICTS = frozenset(_VALID_VERDICTS)
ISSUE_CLASSES = frozenset({"security", "quality", "inactive"})
DEFAULT_ISSUE_CLASS = "security"
UNRESOLVED_REASONS = frozenset({
    "not_reviewed_regex",
    "not_reviewed_joern",
    "not_reviewed_sca",
    "llm_missing_verdict",
    "llm_unrecognised_verdict",
    "llm_call_failed",
    "llm_budget_exhausted",
    "cap_reached",
    "evidence_missing",
    "conflict",
    "not_in_sample",
    "explanation_contradiction",
})


def unresolved_reason_for_exception(exc: BaseException) -> str:
    """Why an LLM call that raised left its work undecided."""
    return "llm_budget_exhausted" if isinstance(exc, LlmBudgetExhausted) else "llm_call_failed"
_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# The only spellings besides the exact enums that count as a decision. Anything
# else — "not sure", "maybe", "not a true positive" — is ambiguous, and an
# ambiguous answer must never dismiss a finding.
_VERDICT_ALIASES = {
    "tp": "true_positive",
    "fp": "false_positive",
    "true positive": "true_positive",
    "false positive": "false_positive",
    "confirmed": "true_positive",
    "dismissed": "false_positive",
}
VERDICT_REASON_MAX_CHARS = 200


def parse_verdict(raw: Any) -> Tuple[Optional[str], Optional[str]]:
    """(verdict, unresolved_reason) for one LLM verdict value. Pure.

    Accepts the exact enums (case-insensitive, `-` read as `_`) and the fixed
    aliases above. Everything else is `(None, reason)` and the caller records the
    finding as `unverified`: `llm_missing_verdict` when nothing usable was
    returned, `llm_unrecognised_verdict` when something was but is not a
    decision. There are no substring or negation heuristics, and nothing
    defaults to false_positive. A literal "unverified" is a real answer, but an
    undecided one, so it carries `evidence_missing`."""
    if raw is None:
        return None, "llm_missing_verdict"
    if not isinstance(raw, str):
        return None, "llm_unrecognised_verdict"
    text = " ".join(raw.split())
    if not text:
        return None, "llm_missing_verdict"
    key = text.lower().replace("-", "_")
    if key in ("true_positive", "false_positive"):
        return key, None
    if key == VERDICT_UNVERIFIED:
        return VERDICT_UNVERIFIED, "evidence_missing"
    alias = _VERDICT_ALIASES.get(key.replace("_", " "))
    if alias:
        return alias, None
    return None, "llm_unrecognised_verdict"


def _record_verdict_problem(usage: Optional[Dict[str, Any]], step: Optional[str], reason: Optional[str]) -> None:
    """Count a model answer that was not a usable verdict, per LLM step."""
    if usage is None or step is None:
        return
    if reason == "llm_unrecognised_verdict":
        record_verdict_event(usage, step, "unrecognised_verdicts")
    elif reason == "llm_missing_verdict":
        record_verdict_event(usage, step, "missing_verdicts")


def _unresolved_verdict_reason(raw: Any, reason: str) -> str:
    """Human text for a finding left unverified because of its verdict value:
    the raw answer (bounded) when there was one."""
    if reason == "llm_missing_verdict":
        return "The model returned no verdict for this finding."
    text = raw if isinstance(raw, str) else repr(raw)
    return f"The model returned an unrecognised verdict: {' '.join(text.split())[:VERDICT_REASON_MAX_CHARS]}"


def _normalize_confidence(raw: Any, verdict: Optional[str]) -> Optional[float]:
    if verdict not in ("true_positive", "false_positive"):
        return None  # an unresolved verdict has no confidence to invent
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return 0.7 if verdict == "true_positive" else 0.5
    if value > 1.0:  # model returned a percentage
        value /= 100.0
    return max(0.0, min(1.0, value))


def _first_code_line(snippet: str) -> str:
    for raw in (snippet or "").splitlines():
        text = re.sub(r"^\s*\d+\s*:\s?", "", raw).strip()
        if len(text) >= 8 and not text.startswith(("//", "#", "*", "/*")):
            return text
    return ""


def reanchor_line(
    source_lines: Sequence[str],
    reported_line: int,
    snippet: str,
    lo: int,
    hi: int,
    *,
    radius: int = 80,
) -> int:
    """Locate the finding by its snippet instead of trusting the reported line.

    The old code clamped out-of-range lines to the chunk edge, which produced
    findings pointing at unrelated code. Here an in-range line that matches its
    snippet is accepted as-is; otherwise the nearest line containing the
    snippet's first real code line wins; only if nothing matches do we clamp."""
    needle = _first_code_line(snippet)
    if 1 <= reported_line <= len(source_lines) and needle and needle in source_lines[reported_line - 1]:
        return reported_line
    if needle:
        best: Optional[int] = None
        lo_idx = max(0, lo - 1 - radius)
        hi_idx = min(len(source_lines), hi + radius)
        for i in range(lo_idx, hi_idx):
            if needle in source_lines[i]:
                candidate = i + 1
                if best is None or abs(candidate - reported_line) < abs(best - reported_line):
                    best = candidate
        if best is not None:
            return best
    return max(lo, min(hi, reported_line))


def normalize_finding(
    raw: Dict[str, Any],
    *,
    file_path: str,
    chunk_start: int,
    chunk_end: int,
    source_lines: Optional[Sequence[str]] = None,
    kind: str = "llm",
    rule_owasp: Optional[Dict[str, str]] = None,
    rule_meta: Optional[Dict[str, Dict[str, str]]] = None,
    usage: Optional[Dict[str, Any]] = None,
    step: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """`usage` + `step`, when given, count verdicts that were missing or not
    recognised (see `parse_verdict`) against that LLM step.

    `rule_owasp` (catalog id -> OWASP label) fills the category for a
    finding that cites a catalog rule without restating its label;
    `rule_meta` (`catalog_rule_index`) does the same for title and CWE, which
    the deep-scan schema also lets the model omit for a catalog rule_id."""
    if not isinstance(raw, dict):
        return None
    try:
        line = int(raw.get("line"))
    except (TypeError, ValueError):
        return None

    snippet = str(raw.get("snippet") or "")
    if source_lines is not None:
        line = reanchor_line(source_lines, line, snippet, chunk_start, chunk_end)
    else:
        line = max(chunk_start, min(chunk_end, line))

    verdict, unresolved_reason = parse_verdict(raw.get("verdict"))
    _record_verdict_problem(usage, step, unresolved_reason)
    severity = str(raw.get("severity") or "MEDIUM").strip().upper()
    if severity not in _VALID_SEVERITIES:
        severity = "MEDIUM"
    rule_id = str(raw.get("rule_id") or "llm-extra").strip() or "llm-extra"
    meta = (rule_meta or {}).get(rule_id) or {}
    cwe = str(raw.get("cwe") or "").strip() or meta.get("cwe") or None
    owasp_category = str(raw.get("owasp_category") or "").strip()
    if owasp_category not in OWASP_TOP_10_2021:
        owasp_category = (
            (rule_owasp or {}).get(rule_id) or meta.get("owasp") or owasp_for_rule(cwe, None)
        )
    title = str(raw.get("title") or "").strip() or meta.get("title") or "Untitled finding"
    reason = str(raw.get("verdict_reason") or "").strip() or "No reason provided by the model."
    if verdict is None:
        # Not a decision: unresolved, never a dismissal. The raw answer goes in
        # the reason so a reviewer can see what the model actually said.
        verdict = VERDICT_UNVERIFIED
        reason = _unresolved_verdict_reason(raw.get("verdict"), unresolved_reason or "")
    ai_fix = raw.get("ai_fix")
    ai_fix = str(ai_fix).strip() if verdict == "true_positive" and ai_fix else None

    kind = str(raw.get("kind") or kind).strip() or "llm"
    finding_out = {
        # What kind of issue it is: the cited catalog rule's class, else security.
        "issue_class": meta.get("issue_class") or DEFAULT_ISSUE_CLASS,
        "decision_stage": "flow_verify" if kind == "flow" else "deep_scan",
        "verdict": verdict,
        "confidence": _normalize_confidence(raw.get("confidence"), verdict),
        "owasp_category": owasp_category,
        "severity": severity,
        "cwe": cwe,
        "rule_id": rule_id,
        "title": title[:500],
        "file_path": file_path,
        "line": line,
        "source": str(raw.get("source") or "").strip()[:300],
        "sink": str(raw.get("sink") or "").strip()[:300],
        "data_flow": str(raw.get("data_flow") or "").strip()[:600],
        "snippet": snippet[:800],
        "verdict_reason": reason,
        "ai_fix": ai_fix,
        "kind": kind,
    }
    if verdict == VERDICT_UNVERIFIED:
        finding_out["unresolved_reason"] = unresolved_reason or "evidence_missing"
    return finding_out


# Re-anchoring can shift one issue's reported line by a line or two between
# overlapping chunks or batched calls; same-CWE findings this close are one issue.
DEDUPE_LINE_WINDOW = 2


def _dedupe_key(finding: Dict[str, Any]) -> tuple:
    """Group by a coarse topic so the same issue reported under two different
    rule_ids across an overlap region collapses into one row. The CWE is
    compared by number, so 'CWE-89' and 'CWE-089' are the same."""
    title = re.sub(r"[^a-z]+", " ", str(finding.get("title") or "").lower()).strip()
    topic = " ".join(title.split()[:3])
    cwe = re.search(r"\d+", str(finding.get("cwe") or ""))
    return (int(cwe.group()) if cwe else topic, bool(cwe))


# Between two reviews of one issue that disagree, the verdicts rank for the
# pairs that involve an undecided answer: a confirmation beats an undecided
# answer, and an undecided answer beats a dismissal (so an ambiguous verdict is
# never silently replaced by a duplicate that said false_positive).
_UNDECIDED_PREFERENCE = {"true_positive": 0, VERDICT_UNVERIFIED: 1, "false_positive": 2}


def _is_better(new: Dict[str, Any], current: Dict[str, Any]) -> bool:
    """Tie-break between two findings with the SAME verdict: severity, then
    confidence. It never prefers one verdict over another as such."""
    cur_rank = _SEVERITY_RANK.get(current["severity"], 9)
    new_rank = _SEVERITY_RANK.get(new["severity"], 9)
    return new_rank < cur_rank or (
        new_rank == cur_rank and (new.get("confidence") or 0) > (current.get("confidence") or 0)
    )


def _call_node(finding: Dict[str, Any]) -> Optional[Tuple[int, int]]:
    """Start position of the call this finding is about, when facts resolved one."""
    call = (finding.get("facts") or {}).get("call") if isinstance(finding.get("facts"), dict) else None
    if call and call.get("start_line") is not None:
        return int(call["start_line"]), int(call.get("start_col") or 0)
    return None


def _same_node(a: Dict[str, Any], b: Dict[str, Any], has_cwe: bool) -> bool:
    """Do two findings refer to the same AST node? With resolved calls: the same
    call start position — two different calls a few lines apart (a count log
    and a getMessage log) stay two findings. Without facts for both, the
    behaviour is what it always was: the same line, or within
    DEDUPE_LINE_WINDOW lines when both carry a CWE."""
    node_a, node_b = _call_node(a), _call_node(b)
    if node_a is not None and node_b is not None:
        return node_a == node_b
    gap = abs(a["line"] - b["line"])
    return gap == 0 or (has_cwe and gap <= DEDUPE_LINE_WINDOW)


def _has_validator_proof(finding: Dict[str, Any]) -> bool:
    facts = finding.get("facts")
    outcomes = facts.get("validators") if isinstance(facts, dict) else None
    return any(o.get("outcome") in ("negative_proof", "positive_fact") for o in outcomes or [])


def _evidence_score(finding: Dict[str, Any]) -> int:
    """How much a finding actually shows: a named source, sink and data flow,
    plus the sink's callee on the anchored call."""
    score = sum(1 for key in ("source", "sink", "data_flow") if (finding.get(key) or "").strip())
    facts = finding.get("facts")
    call = (facts or {}).get("call") if isinstance(facts, dict) else None
    sink = _squash(finding.get("sink"))
    if call and sink and (call.get("callee") or "") and call["callee"] in sink:
        score += 1
    return score


def _note_dedupe(survivor: Dict[str, Any], discarded: Dict[str, Any], *, conflict: bool = False) -> None:
    """The survivor remembers what the merge threw away (a decision-history row)."""
    survivor.setdefault("decisions", []).append({
        "stage": "dedupe", "actor": "merge_dedupe",
        "verdict": survivor.get("verdict"), "confidence": survivor.get("confidence"),
        "unresolved_reason": survivor.get("unresolved_reason"),
        "verdict_reason": survivor.get("verdict_reason"),
        "detail": {
            "discarded_verdict": discarded.get("verdict"),
            "discarded_rule_id": discarded.get("rule_id"),
            "discarded_reason": _squash(discarded.get("verdict_reason"))[:300],
            "conflict": conflict,
        },
    })


def _merge_pair(
    new: Dict[str, Any], current: Dict[str, Any], usage: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    """Two findings about one AST node, one survivor.

    Same verdict: the higher severity, then confidence. Different verdicts: an
    undecided answer is never replaced by a dismissal and a confirmation beats
    an undecided answer; between a confirmation and a dismissal a deterministic
    validator proof decides, then the finding that shows more evidence, and on
    equal evidence neither wins — the result is `unverified` with the conflict
    reason, both rationales kept. Taking the more alarming answer by default is
    the thing this replaces."""
    if new["verdict"] == current["verdict"]:
        winner, loser = (new, current) if _is_better(new, current) else (current, new)
        _note_dedupe(winner, loser)
        return winner
    verdicts = {new["verdict"], current["verdict"]}
    if VERDICT_UNVERIFIED in verdicts:
        a_rank = _UNDECIDED_PREFERENCE.get(new["verdict"], 2)
        b_rank = _UNDECIDED_PREFERENCE.get(current["verdict"], 2)
        winner, loser = (new, current) if a_rank < b_rank else (current, new)
        _note_dedupe(winner, loser)
        return winner
    proof_new, proof_current = _has_validator_proof(new), _has_validator_proof(current)
    if proof_new != proof_current:
        winner, loser = (new, current) if proof_new else (current, new)
        _note_dedupe(winner, loser)
        return winner
    score_new, score_current = _evidence_score(new), _evidence_score(current)
    if score_new != score_current:
        winner, loser = (new, current) if score_new > score_current else (current, new)
        _note_dedupe(winner, loser)
        return winner
    bump_counter(usage, "dedupe_conflicts", "total")
    merged = dict(current)
    reasons = [
        f"[{f['verdict']}] {(f.get('verdict_reason') or 'no reason').strip()}" for f in (current, new)
    ]
    merged.update(
        verdict=VERDICT_UNVERIFIED, unresolved_reason="conflict", confidence=None, ai_fix=None,
        severity=min((current["severity"], new["severity"]), key=lambda s: _SEVERITY_RANK.get(s, 9)),
        verdict_reason="Two reviews of this call disagree and show equal evidence. " + " | ".join(reasons),
    )
    _note_dedupe(merged, new, conflict=True)
    return merged


def merge_dedupe(
    findings: List[Dict[str, Any]], usage: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """Merge findings that describe the same issue at the same AST node (same
    cwe-or-topic key, and `_same_node`). See `_merge_pair` for which survives."""
    best: List[Tuple[tuple, Dict[str, Any]]] = []
    for f in sorted(findings, key=lambda x: x["line"]):
        key = _dedupe_key(f)
        for i, (other_key, current) in enumerate(best):
            if other_key != key or not _same_node(f, current, key[1]):
                continue
            best[i] = (key, _merge_pair(f, current, usage))
            break
        else:
            best.append((key, f))
    return sorted((f for _, f in best), key=lambda f: (f["line"], f["rule_id"]))


# --- suppression / enrichment ----------------------------------------------

def _is_noisy_rule(rule_id: str) -> bool:
    rid = (rule_id or "").lower()
    return rid in _SQL_CONCAT_CATALOG_IDS or ("sql" in rid and "concat" in rid)


def _is_unanalyzable_meta_finding(finding: Dict[str, Any]) -> bool:
    """Drop LLM 'I cannot analyze this bytecode' placeholders — not real findings."""
    if float(finding.get("confidence") or 0.0) > 0.1:
        return False
    path = (finding.get("file_path") or "").lower()
    if path.endswith(".class") or path.endswith(".jar"):
        return True
    blob = " ".join([
        finding.get("title") or "",
        finding.get("verdict_reason") or "",
        finding.get("data_flow") or "",
        finding.get("snippet") or "",
    ])
    return bool(_UNANALYZABLE_META_RE.search(blob))


def _anchored_line_from_context(context_text: str) -> str:
    """Pull just the flagged line (marked '<--' by build_code_context) out of an
    enriched context window, so logging-call suppression only judges the actual
    finding line, not an unrelated logger call a few lines away."""
    for line in context_text.splitlines():
        if line.rstrip().endswith("<--"):
            return line
    return ""


PUBLISH = "publish"
DROP = "drop"
DEMOTE = "demote"  # publish, but as `unverified` / evidence_missing

# A log call cannot be the sink of these weakness classes: SQL injection, XSS,
# command injection, path traversal, XXE, SSRF, deserialization, LDAP. A finding
# of one of them anchored on a logger call is blaming the wrong line (SAST-01-030).
# Every other class is a legitimate thing to find on a log line — forged or
# injected log content (CWE-117), secrets and sensitive data written to a log
# (CWE-532, 312/313/359, 200/209/497, 798) — so those are never dropped here, and
# neither is a finding with no CWE (`suppress_no_cwe` decides those).
LOG_LINE_IMPOSSIBLE_CWES = frozenset({89, 79, 78, 22, 611, 918, 502, 90})
MISSING_EVIDENCE_NOTE = (
    "Published as unverified: the model called this a SQL injection but neither the "
    "flagged statement builds the query nor does the named source appear in the method."
)


def _cwe_number(cwe: Any) -> Optional[int]:
    digits = re.search(r"\d+", str(cwe or ""))
    return int(digits.group()) if digits else None


def _squash(text: Any) -> str:
    return " ".join(str(text or "").split())


def _is_log_call(finding: Dict[str, Any], snippet: str, anchored: str) -> bool:
    """Is the flagged line a call on a logger? Decided from the resolved call's
    receiver type whenever the finding has facts (any slf4j / log4j / jul /
    commons-logging / jboss logger, however the variable is named, plus
    `console` and NGXLogger in TypeScript); the old spelling regex is only the
    fallback for a finding with none."""
    facts = finding.get("facts")
    if isinstance(facts, dict) and facts:
        return output_sinks.sink_class(facts, file_path=str(finding.get("file_path") or "")).kind == output_sinks.LOGGER
    return bool(
        _LOGGING_CALL_RE.search(snippet) or (anchored and _LOGGING_CALL_RE.search(anchored))
    )


def _builds_sql_in_own_statement(finding: Dict[str, Any], window_builds_sql: bool) -> bool:
    """Does the finding's own statement (the resolved call, else the enclosing
    statement) construct a query? A concatenation fifteen lines away, in another
    statement, does not count when facts say where the statement is."""
    facts = finding.get("facts")
    if isinstance(facts, dict) and facts:
        own = (facts.get("call") or {}).get("text") or facts.get("statement")
        if own:
            return bool(_SQL_BUILD_RE.search(own))
    return window_builds_sql


def _has_source_evidence(finding: Dict[str, Any]) -> bool:
    """Is the model's named `source` actually in the code? It must appear in the
    enclosing method, or on the flow path for a flow finding. Without facts a
    named source counts, as it always did."""
    source = (finding.get("source") or "").strip()
    if not source:
        return False
    if finding.get("kind") == "flow" and finding.get("flow_path"):
        return any(
            source_in_text(source, f"{step.get('snippet') or ''}\n{step.get('label') or ''}")
            for step in finding.get("flow_path") or []
        )
    facts = finding.get("facts")
    if isinstance(facts, dict) and "source_in_method" in facts:
        return bool(facts["source_in_method"])
    return True


def _record_publish_drop(
    usage: Optional[Dict[str, Any]], finding: Dict[str, Any], reason: str, cwe: Optional[int]
) -> None:
    bump_counter(usage, "publish_filter", f"{reason}_dropped.CWE-{cwe}" if cwe else f"{reason}_dropped")
    append_record(usage, "publish_filter_drops", {
        "rule_id": finding.get("rule_id"), "file": finding.get("file_path"),
        "line": finding.get("line"), "cwe": f"CWE-{cwe}" if cwe else None, "reason": reason,
    })


def publish_decision(
    finding: Dict[str, Any],
    context_text: str = "",
    *,
    suppress_no_cwe: bool = True,
    suppress_http_findings: bool = False,
    suppress_low_confidence_false_positives: bool = False,
    usage: Optional[Dict[str, Any]] = None,
) -> str:
    """Evidence-based suppression: `PUBLISH`, `DROP`, or `DEMOTE` (publish, but
    as unverified because the evidence a SQL true positive needs is missing).

    `context_text` should be the enriched source window, not the model's
    truncated snippet — a sink-only snippet whose query is built 20 lines above
    otherwise looks unevidenced when it is not.

    `suppress_no_cwe` (default True) drops any finding with no CWE mapping —
    too generic to map to a known weakness class is treated as not actionable.
    `suppress_http_findings` (default False, opt-in per project via the
    https-enforced-suppress-http scan limitation) drops findings about
    cleartext HTTP / missing HTTPS enforcement for projects that have told us
    HTTPS is enforced at a layer the scan can't see.
    `suppress_low_confidence_false_positives` (default False, real default True
    via the low-confidence-fp-suppressed scan limitation) drops any
    false_positive-verdict finding at or below
    FALSE_POSITIVE_SUPPRESS_CONFIDENCE_CEILING — the model confidently
    dismissed it, regardless of rule_id.

    A finding anchored on a logger call is dropped only when its CWE is one a
    log call cannot be (`LOG_LINE_IMPOSSIBLE_CWES`). A noisy SQL-concatenation
    true positive is published as a true positive only with evidence — its own
    statement builds the query, or its named source is really in the method;
    model confidence never substitutes for either."""
    if suppress_no_cwe and not (finding.get("cwe") or "").strip():
        return DROP
    if suppress_http_findings and _is_http_related_finding(finding):
        return DROP
    # A dismissal settled by a deterministic proof (validators) is kept as a row
    # with its proof, so the report shows the scanner looked at it; the two
    # drops below are about *model* dismissals, and a proof carries no
    # confidence to compare.
    proven = _has_validator_proof(finding)
    if (
        suppress_low_confidence_false_positives
        and finding.get("verdict") == "false_positive"
        and not proven
        and float(finding.get("confidence") or 0.0) <= FALSE_POSITIVE_SUPPRESS_CONFIDENCE_CEILING
    ):
        return DROP
    if _is_unanalyzable_meta_finding(finding):
        return DROP

    snippet = (finding.get("snippet") or "").strip()
    anchored = _anchored_line_from_context(context_text) if context_text else ""
    cwe = _cwe_number(finding.get("cwe"))
    if cwe in LOG_LINE_IMPOSSIBLE_CWES and _is_log_call(finding, snippet, anchored):
        _record_publish_drop(usage, finding, "logging_line", cwe)
        return DROP

    combined = " ".join([
        finding.get("title") or "",
        finding.get("data_flow") or "",
        finding.get("sink") or "",
        snippet,
        context_text,
    ]).lower()

    window_builds_sql = bool(_SQL_BUILD_RE.search(combined))

    # A bare ResultSet read with no query construction anywhere nearby is the
    # single most common false positive in Java scans. Still safe to drop.
    if _RESULTSET_READ_RE.search(snippet) and not window_builds_sql:
        return DROP

    if _is_noisy_rule(finding.get("rule_id", "")):
        verdict = finding.get("verdict")
        if verdict == "false_positive" and not proven:
            _record_publish_drop(usage, finding, "noisy_fp", cwe)
            bump_counter(usage, "publish_filter", "noisy_fp_dropped")
            return DROP  # generic catalog echo marked FP — no tuning value
        if verdict != "true_positive":
            return PUBLISH  # undecided: nobody has judged it, so nothing may be dropped on a guess
        if _builds_sql_in_own_statement(finding, window_builds_sql) or _has_source_evidence(finding):
            return PUBLISH
        bump_counter(usage, "publish_filter", "noisy_tp_demoted_unverified")
        return DEMOTE

    return PUBLISH


def should_publish_finding(finding: Dict[str, Any], context_text: str = "", **kwargs: Any) -> bool:
    """`publish_decision` as a yes/no: anything but a drop is published (a
    demotion is published as unverified, see `apply_publish_decision`)."""
    return publish_decision(finding, context_text, **kwargs) != DROP


def apply_publish_decision(finding: Dict[str, Any], decision: str) -> Dict[str, Any]:
    """Carry out a `DEMOTE` on the finding in place: it stays visible, but as
    unresolved with the missing evidence named, never as a confirmed injection."""
    if decision != DEMOTE:
        return finding
    prior = (finding.get("verdict_reason") or "").strip()
    finding.update(
        verdict=VERDICT_UNVERIFIED, unresolved_reason="evidence_missing",
        confidence=None, ai_fix=None,
        verdict_reason=f"{MISSING_EVIDENCE_NOTE} Model's reasoning: {prior}" if prior else MISSING_EVIDENCE_NOTE,
    )
    finding.setdefault("decisions", []).append({
        "stage": "publish_filter", "actor": "noisy_rule_evidence",
        "verdict": VERDICT_UNVERIFIED, "confidence": None,
        "unresolved_reason": "evidence_missing", "verdict_reason": finding["verdict_reason"],
    })
    return finding


def build_code_context(
    source_text: str,
    line: int,
    llm_snippet: str = "",
    *,
    before: int = CONTEXT_LINES_BEFORE,
    after: int = CONTEXT_LINES_AFTER,
    max_chars: int = SNIPPET_MAX_CHARS,
) -> str:
    """Numbered source excerpt around the finding line for UI/PDF reports."""
    lines = source_text.splitlines()
    if not lines:
        return (llm_snippet or "").strip()[:max_chars]

    idx = max(0, min(len(lines) - 1, line - 1))
    start = max(0, idx - before)
    end = min(len(lines), idx + after + 1)
    numbered = []
    for i in range(start, end):
        marker = "  <--" if i == idx else ""
        numbered.append(f"{i + 1}: {lines[i]}{marker}")
    block = "\n".join(numbered)
    if not block.strip() and llm_snippet:
        return llm_snippet.strip()[:max_chars]
    return block[:max_chars]


def finalize_findings(
    findings: List[Dict[str, Any]],
    source_text: str,
    *,
    suppress_no_cwe: bool = True,
    suppress_http_findings: bool = False,
    suppress_low_confidence_false_positives: bool = False,
    usage: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Enrich snippets with real source context, *then* apply suppression
    against that context. Order matters: judging a sink-only snippet before
    enrichment is what caused genuine injections to be filtered out."""
    out: List[Dict[str, Any]] = []
    for finding in findings:
        context = build_code_context(
            source_text, finding["line"], finding.get("snippet") or "",
        )
        decision = publish_decision(
            finding, context,
            suppress_no_cwe=suppress_no_cwe, suppress_http_findings=suppress_http_findings,
            suppress_low_confidence_false_positives=suppress_low_confidence_false_positives,
            usage=usage,
        )
        if decision == DROP:
            continue
        enriched = dict(finding)
        enriched["snippet"] = context
        out.append(apply_publish_decision(enriched, decision))
    return out


def _retry_match(old: Dict[str, Any], candidates: Sequence[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The retry's answer about the same issue: same rule on the same line,
    else the same rule within the dedupe window, else the same CWE there."""
    def near(c: Dict[str, Any], window: int) -> bool:
        return abs(int(c.get("line") or 0) - int(old.get("line") or 0)) <= window

    for same, window in (
        (lambda c: c.get("rule_id") == old.get("rule_id"), 0),
        (lambda c: c.get("rule_id") == old.get("rule_id"), DEDUPE_LINE_WINDOW),
        (lambda c: _cwe_number(c.get("cwe")) == _cwe_number(old.get("cwe")), DEDUPE_LINE_WINDOW),
    ):
        for c in candidates:
            if same(c) and near(c, window):
                return c
    return None


def resolve_contradictions(
    findings: List[Dict[str, Any]],
    source_text: str,
    *,
    file_path: str = "",
    usage: Optional[Dict[str, Any]] = None,
    step: str = "scan_deep_files",
    retry: Optional[Callable[[str], List[Dict[str, Any]]]] = None,
    labels: Optional[Sequence[str]] = None,
) -> List[Dict[str, Any]]:
    """Check each finding's explanation against its code and verdict
    (`explanation_check`). A contradiction earns ONE targeted retry — `retry` is
    called with the `Deterministic facts:` block naming the contradictions and
    returns the model's fresh findings — when the stage still has budget. A
    finding whose retry is consistent is replaced by the retry's; one whose
    retry still contradicts, or that had no retry, becomes `unverified` /
    `explanation_contradiction`. Nothing is ever turned into a false positive
    by this check."""
    prepare_findings(findings, source_text, file_path=file_path, usage=usage, validators=True)
    contradicted = explanation_check.annotate(findings, source_text, usage=usage)
    if not contradicted:
        return findings
    replacements: Dict[int, Dict[str, Any]] = {}
    if retry is not None and stage_has_budget(usage, step):
        bump_counter(usage, "explanation_contradictions", "retries")
        block = explanation_check.contradictions_block(contradicted, labels=labels)
        try:
            fresh = list(retry(block) or [])
        except Exception:  # noqa: BLE001 - a failed retry leaves the contradiction standing
            fresh = []
        if fresh:
            prepare_findings(fresh, source_text, file_path=file_path, usage=usage, validators=True)
            for old in contradicted:
                match = _retry_match(old, fresh)
                if match is None:
                    continue
                if explanation_check.annotate([match], source_text, usage=usage):
                    old["contradictions"] = match["contradictions"]
                    continue
                match["decisions"] = list(old.get("decisions") or []) + [{
                    "stage": "explanation_retry", "actor": "explanation_check",
                    "verdict": match.get("verdict"), "confidence": match.get("confidence"),
                    "unresolved_reason": match.get("unresolved_reason"),
                    "verdict_reason": match.get("verdict_reason"),
                    "detail": {"resolved_contradictions": old["contradictions"],
                               "first_verdict": old.get("verdict")},
                }]
                replacements[id(old)] = match
                bump_counter(usage, "explanation_contradictions", "retry_resolved")
    out: List[Dict[str, Any]] = []
    for finding in findings:
        finding = replacements.get(id(finding), finding)
        if finding.get("contradictions"):
            explanation_check.mark_contradicted(finding)
        out.append(finding)
    return out


def dedupe_and_finalize(
    findings: List[Dict[str, Any]],
    source_text: str,
    *,
    file_path: str = "",
    usage: Optional[Dict[str, Any]] = None,
    occurrence_validators: bool = True,
    suppress_no_cwe: bool = True,
    suppress_http_findings: bool = False,
    suppress_low_confidence_false_positives: bool = False,
) -> List[Dict[str, Any]]:
    """One file's findings from raw to publishable: attach occurrence facts and
    run the deterministic validators on each occurrence (EPIC-01), then dedupe,
    enrich and filter. The order is the point — facts and proofs exist before
    anything merges two findings or decides whether one is published."""
    prepare_findings(
        findings, source_text, file_path=file_path, usage=usage, validators=occurrence_validators,
    )
    return finalize_findings(
        merge_dedupe(findings, usage=usage), source_text,
        suppress_no_cwe=suppress_no_cwe, suppress_http_findings=suppress_http_findings,
        suppress_low_confidence_false_positives=suppress_low_confidence_false_positives,
        usage=usage,
    )


# --- LLM plumbing -----------------------------------------------------------

def files_for_risk_levels(
    module_plan: Dict[str, Any],
    levels: Set[str],
    *,
    skip_tests: bool = True,
) -> List[Dict[str, Any]]:
    """Files at the given path-heuristic risk levels, excluding non-source,
    schema/CVS/log4j paths and (by default) test code — all of which stay in
    Discovery but are not finding-scanned."""
    wanted = {str(level).upper() for level in levels}
    return [
        entry for entry in module_plan.get("files", [])
        if str(entry.get("risk_level") or "").upper() in wanted
        and not is_non_source_path(entry.get("path") or "")
        and not is_excluded_from_finding_scan(entry.get("path") or "")
        and not (skip_tests and is_test_path(entry.get("path") or ""))
    ]


def files_for_paths(module_plan: Dict[str, Any], paths: Sequence[str]) -> List[Dict[str, Any]]:
    """Resolve a path list back to full file entries, in `paths` order.

    Used where the caller has already decided the exact working set (e.g. the
    capped/overflow-routed deep_scan_paths / triage_scan_paths built by
    node_map_modules_and_risk) and just needs the corresponding entries rather
    than re-deriving them from risk_level."""
    by_path = {entry["path"]: entry for entry in module_plan.get("files", [])}
    return [by_path[p] for p in paths if p in by_path]


def scan_chunk(
    *,
    file_path: str,
    chunk: Dict[str, Any],
    catalog: List[Dict[str, Any]],
    stack_context: str,
    skeleton: str = "",
    source_lines: Optional[Sequence[str]] = None,
    usage: Optional[Dict[str, Any]] = None,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    call_llm_fn: Callable[..., str] = call_llm,
    system_prompt: Optional[str] = None,
    llm_step: str = "scan_deep_files",
    kind: str = "llm",
    omit_span: Optional[Tuple[int, int]] = None,
    extra_user: str = "",
) -> Dict[str, Any]:
    """Scan one chunk. Returns {"findings": [...], "error": str|None}.

    `extra_user`, when given, is appended to the user prompt: the retry of an
    answer whose explanation contradicted the code carries a
    `Deterministic facts:` block naming what was wrong.

    A malformed JSON response gets one retry with an explicit repair nudge; if
    it still fails the error is returned rather than silently yielding zero
    findings, which is how the old version lost whole chunks.

    `usage` must be the shared scan usage dict so the $2 Bedrock cutoff in
    `llm_client._resolve_provider_for_call` can see running cost_usd.
    """
    system = system_prompt or build_system_prompt(catalog, stack_context)
    user = build_user_prompt(
        file_path=file_path, chunk_text=chunk["text"],
        start_line=chunk["start_line"], skeleton=skeleton, omit_span=omit_span,
    )
    if extra_user:
        user = user + "\n\n" + extra_user
    rule_meta = catalog_rule_index(catalog)

    def _call(prompt: str) -> str:
        with _INFLIGHT:
            return call_llm_fn(
                system, prompt,
                max_tokens=4096, temperature=0.0,
                usage=usage, step=llm_step,
                provider=llm_provider, model=llm_model, json_mode=True,
            )

    try:
        raw_text = _call(user)
        items, err = parse_llm_json_array(raw_text)
        if err and not items:
            retry_user = (
                user
                + "\n\nYour previous response could not be parsed as JSON. "
                'Respond with the {"findings": [...]} JSON object only — no prose, '
                "no markdown fences."
            )
            raw_text = _call(retry_user)
            items, err = parse_llm_json_array(raw_text)
    except Exception as exc:  # one bad chunk must not kill the tier
        return {
            "findings": [], "error": f"{type(exc).__name__}: {exc}",
            "budget_exhausted": isinstance(exc, LlmBudgetExhausted),
        }

    cache_hit = last_call_was_cache_hit()  # same thread, right after the call parsed above
    findings: List[Dict[str, Any]] = []
    for item in items:
        norm = normalize_finding(
            item, file_path=file_path,
            chunk_start=chunk["start_line"], chunk_end=chunk["end_line"],
            source_lines=source_lines, kind=kind, rule_meta=rule_meta,
            usage=usage, step=llm_step,
        )
        if norm is not None:
            norm["result_cache_hit"] = cache_hit
            findings.append(norm)
    return {"findings": findings, "error": err if (err and not items) else None}


def _budget_fallback_findings(
    *,
    rel_path: str,
    text: str,
    lang: Optional[str],
    spans: Sequence[Tuple[int, int]],
    rules: List[RegexRule],
    active_frameworks: Optional[Set[str]],
    dependency_index: Optional[Dict[str, List[Optional[str]]]],
    repo_root: Path,
) -> List[Dict[str, Any]]:
    """Regex hits for the chunks the LLM budget ran out on, as `unverified`.

    Past the spend cutoff a deep-scan chunk gets no answer at all, and unlike
    the triage tier a deep-scan file is not otherwise regex-scanned, so the
    work would simply vanish. The catalog pass is local and free: its hits in
    just those line ranges are recorded as unresolved (`llm_budget_exhausted`)
    so the gap shows up as undecided work, never as a clean file."""
    if not spans:
        return []
    scanned = scan_one_file(
        repo_root, rel_path, "", rules, file_lang=lang,
        active_frameworks=active_frameworks, dependency_index=dependency_index,
    )
    hits = [
        h for h in scanned["hits"]
        if any(start <= int(h.get("line") or 0) <= end for start, end in spans)
    ]
    out = findings_from_hits(
        file_path=rel_path, source_text=text, hits=hits,
        rules_by_id={rule.id: rule for rule in rules},
    )
    for finding in out:
        finding["file_path"] = rel_path
        if finding["verdict"] == VERDICT_UNVERIFIED:
            finding["unresolved_reason"] = "llm_budget_exhausted"
            finding["verdict_reason"] = BUDGET_EXHAUSTED_REASON
    return out


def scan_file(
    *,
    repo_root: Path,
    rel_path: str,
    rules: List[RegexRule],
    active_frameworks: Optional[Set[str]] = None,
    dependency_index: Optional[Dict[str, List[Optional[str]]]] = None,
    priority_rule_ids: Optional[Set[str]] = None,
    stack_context: str = "",
    usage: Optional[Dict[str, Any]] = None,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    call_llm_fn: Callable[..., str] = call_llm,
    on_chunk_start: Optional[Callable[[int, int, str], None]] = None,
    chunk_workers: int = DEFAULT_CHUNK_WORKERS,
    catalog: Optional[List[Dict[str, Any]]] = None,
    system_prompt: Optional[str] = None,
    llm_step: str = "scan_deep_files",
    suppress_no_cwe: bool = True,
    suppress_http_findings: bool = False,
    suppress_low_confidence_false_positives: bool = False,
    occurrence_validators: bool = True,
) -> Dict[str, Any]:
    text = _read_text(repo_root, rel_path)
    if text is None:
        return {
            "file_path": rel_path, "chunks": 0, "findings": [],
            "tp_count": 0, "fp_count": 0, "read_error": True, "chunk_errors": [],
        }

    skip_reason = is_non_analyzable_file(repo_root, rel_path, text)
    if skip_reason:
        return {
            "file_path": rel_path, "chunks": 0, "findings": [],
            "tp_count": 0, "fp_count": 0, "skipped_non_source": True,
            "skip_reason": skip_reason, "chunk_errors": [],
        }

    lang = lang_for_path(rel_path)
    if catalog is None:
        catalog = trim_catalog(rules_for_prompt(
            rules, lang, active_frameworks,
            dependency_index=dependency_index, priority_rule_ids=priority_rule_ids,
        ))
    if system_prompt is None:
        system_prompt = build_system_prompt(catalog, stack_context)

    chunks = chunk_file(text, lang)
    source_lines = text.splitlines()
    # Single-chunk files already contain everything; the skeleton is redundant.
    skeleton_entries = build_file_skeleton_entries(text, lang) if len(chunks) > 1 else []
    omit_span = leading_license_header_span(source_lines)

    def _run(indexed: Tuple[int, Dict[str, Any]]) -> Tuple[int, Dict[str, Any]]:
        idx, chunk = indexed
        if on_chunk_start is not None:
            with _CALLBACK_LOCK:
                on_chunk_start(idx, len(chunks), rel_path)
        skeleton = (
            skeleton_for_chunk(skeleton_entries, chunk["start_line"], chunk["end_line"])
            if skeleton_entries else ""
        )
        def _scan(extra_user: str = "") -> Dict[str, Any]:
            return scan_chunk(
                file_path=rel_path, chunk=chunk, catalog=catalog,
                stack_context=stack_context, skeleton=skeleton,
                source_lines=source_lines, usage=usage,
                llm_provider=llm_provider, llm_model=llm_model,
                call_llm_fn=call_llm_fn, system_prompt=system_prompt,
                llm_step=llm_step, kind="llm", omit_span=omit_span,
                extra_user=extra_user,
            )

        outcome = _scan()
        if occurrence_validators and outcome["findings"]:
            outcome["findings"] = resolve_contradictions(
                outcome["findings"], text, file_path=rel_path, usage=usage, step=llm_step,
                retry=lambda block: _scan(block)["findings"],
            )
        return idx, outcome

    indexed_chunks = list(enumerate(chunks, start=1))
    if len(indexed_chunks) > 1 and chunk_workers > 1:
        with ThreadPoolExecutor(max_workers=min(chunk_workers, len(indexed_chunks))) as pool:
            outcomes = list(pool.map(_run, indexed_chunks))
    else:
        outcomes = [_run(item) for item in indexed_chunks]

    all_findings: List[Dict[str, Any]] = []
    chunk_errors: List[str] = []
    budget_spans: List[Tuple[int, int]] = []
    for idx, outcome in sorted(outcomes, key=lambda pair: pair[0]):
        all_findings.extend(outcome["findings"])
        if outcome.get("error"):
            chunk_errors.append(outcome["error"])
        if outcome.get("budget_exhausted"):
            chunk = chunks[idx - 1]
            budget_spans.append((chunk["start_line"], chunk["end_line"]))

    merged = dedupe_and_finalize(
        all_findings, text, file_path=rel_path, usage=usage,
        occurrence_validators=occurrence_validators,
        suppress_no_cwe=suppress_no_cwe, suppress_http_findings=suppress_http_findings,
        suppress_low_confidence_false_positives=suppress_low_confidence_false_positives,
    )
    unverified = _budget_fallback_findings(
        rel_path=rel_path, text=text, lang=lang, spans=budget_spans, rules=rules,
        active_frameworks=active_frameworks, dependency_index=dependency_index,
        repo_root=repo_root,
    )
    merged = merged + unverified
    tp_count = sum(1 for f in merged if f["verdict"] == "true_positive")
    fp_count = sum(1 for f in merged if f["verdict"] == "false_positive")
    return {
        "file_path": rel_path,
        "chunks": len(chunks),
        "findings": merged,
        "tp_count": tp_count,
        "fp_count": fp_count,
        "unverified_count": sum(1 for f in merged if f["verdict"] == VERDICT_UNVERIFIED),
        "read_error": False,
        "chunk_errors": chunk_errors,
    }


def system_prompt_is_cached(system: str, provider: Optional[str], model: Optional[str]) -> bool:
    """Whether call_llm will serve `system` from the provider prompt cache."""
    return (provider or PROVIDER_BEDROCK) == PROVIDER_BEDROCK and should_cache_system_prompt(system, model)


def _route_batch_item(item: Any, paths: Sequence[str]) -> Optional[str]:
    if not isinstance(item, dict):
        return None
    named = str(item.get("file") or item.get("file_path") or "").strip().replace("\\", "/")
    if named in paths:
        return named
    if named:
        tail = [p for p in paths if p.endswith("/" + named) or named.endswith("/" + p)]
        if len(tail) == 1:
            return tail[0]
        base = named.rsplit("/", 1)[-1]
        by_base = [p for p in paths if p.rsplit("/", 1)[-1] == base]
        if len(by_base) == 1:
            return by_base[0]
    return paths[0] if len(paths) == 1 else None


def scan_file_batch(
    *,
    files: Sequence[Tuple[str, str]],
    catalog: List[Dict[str, Any]],
    system_prompt: str,
    usage: Optional[Dict[str, Any]] = None,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    call_llm_fn: Callable[..., str] = call_llm,
    llm_step: str = "scan_deep_files",
    suppress_no_cwe: bool = True,
    suppress_http_findings: bool = False,
    suppress_low_confidence_false_positives: bool = False,
    occurrence_validators: bool = True,
) -> Optional[List[Dict[str, Any]]]:
    """Deep-scan several small, single-chunk files ((path, text) each) in one
    call. Returns one scan_file-shaped result per file, in order, or None when
    the call failed or never parsed — the caller then scans each file alone,
    so a bad batch costs a retry, never coverage."""
    paths = [p for p, _t in files]
    lines_by_path = {p: t.splitlines() for p, t in files}
    user = build_batch_user_prompt([
        (p, t, leading_license_header_span(lines_by_path[p])) for p, t in files
    ])

    def _call(prompt: str) -> str:
        with _INFLIGHT:
            return call_llm_fn(
                system_prompt, prompt,
                max_tokens=4096, temperature=0.0,
                usage=usage, step=llm_step,
                provider=llm_provider, model=llm_model, json_mode=True,
            )

    try:
        items, err = parse_llm_json_array(_call(user))
        if err and not items:
            items, err = parse_llm_json_array(_call(
                user + '\n\nYour previous response could not be parsed as JSON. Respond with the '
                '{"findings": [...]} JSON object only — no prose, no markdown fences.'
            ))
    except Exception:  # noqa: BLE001 — fall back to per-file scans
        return None
    if err and not items:
        return None

    rule_meta = catalog_rule_index(catalog)
    cache_hit = last_call_was_cache_hit()
    by_path: Dict[str, List[Dict[str, Any]]] = {p: [] for p in paths}
    unrouted = 0
    for item in items:
        path = _route_batch_item(item, paths)
        if path is None:
            unrouted += 1
            continue
        lines = lines_by_path[path]
        norm = normalize_finding(
            item, file_path=path, chunk_start=1, chunk_end=max(1, len(lines)),
            source_lines=lines, kind="llm", rule_meta=rule_meta,
            usage=usage, step=llm_step,
        )
        if norm is not None:
            norm["result_cache_hit"] = cache_hit
            by_path[path].append(norm)

    results = []
    for path, text in files:
        if occurrence_validators and by_path[path]:
            lines = lines_by_path[path]

            def _retry(block: str, path: str = path, text: str = text, lines: Sequence[str] = lines):
                # A batch cannot be asked about one file; the retry is the same
                # file reviewed alone, with the contradiction named.
                return scan_chunk(
                    file_path=path, chunk={"text": text, "start_line": 1, "end_line": max(1, len(lines))},
                    catalog=catalog, stack_context="", source_lines=lines, usage=usage,
                    llm_provider=llm_provider, llm_model=llm_model, call_llm_fn=call_llm_fn,
                    system_prompt=system_prompt, llm_step=llm_step, kind="llm", extra_user=block,
                )["findings"]

            by_path[path] = resolve_contradictions(
                by_path[path], text, file_path=path, usage=usage, step=llm_step, retry=_retry,
            )
        merged = dedupe_and_finalize(
            by_path[path], text, file_path=path, usage=usage,
            occurrence_validators=occurrence_validators,
            suppress_no_cwe=suppress_no_cwe, suppress_http_findings=suppress_http_findings,
            suppress_low_confidence_false_positives=suppress_low_confidence_false_positives,
        )
        tp_count = sum(1 for f in merged if f["verdict"] == "true_positive")
        fp_count = sum(1 for f in merged if f["verdict"] == "false_positive")
        results.append({
            "file_path": path, "chunks": 1, "findings": merged,
            "tp_count": tp_count, "fp_count": fp_count,
            "unverified_count": sum(1 for f in merged if f["verdict"] == VERDICT_UNVERIFIED),
            "read_error": False, "batched_with": len(files),
            "chunk_errors": [f"{unrouted} finding(s) in a {len(files)}-file batch named no known file"]
            if unrouted else [],
        })
    return results


def plan_deep_scan_batches(
    files: Sequence[Tuple[int, str, str]],
    *,
    char_budget: int = BATCH_CHAR_BUDGET,
    max_files: int = BATCH_MAX_FILES,
) -> List[List[Tuple[int, str, str]]]:
    """Greedy, order-preserving packing of (position, path, text) small files
    of one language into batches under `char_budget` / `max_files`."""
    batches: List[List[Tuple[int, str, str]]] = []
    current: List[Tuple[int, str, str]] = []
    size = 0
    for item in files:
        length = len(item[2])
        if current and (size + length > char_budget or len(current) >= max_files):
            batches.append(current)
            current, size = [], 0
        current.append(item)
        size += length
    if current:
        batches.append(current)
    return batches


def _log_chunk_start(chunk_index: int, chunk_total: int, file_path: str) -> None:
    if chunk_total > 1:
        print(f"  LLM chunk {chunk_index}/{chunk_total} for {file_path}…", flush=True)


def build_report_from_file_results(file_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Roll up per-file scan results into the same report shape as generate_report."""
    by_owasp: Dict[str, Dict[str, int]] = {}
    tp_count = fp_count = unverified_count = 0
    for file_result in file_results:
        for finding in file_result.get("findings", []):
            bucket = by_owasp.setdefault(
                finding["owasp_category"],
                {"true_positive": 0, "false_positive": 0, VERDICT_UNVERIFIED: 0},
            )
            bucket[finding["verdict"]] = bucket.get(finding["verdict"], 0) + 1
            # Regex-only findings are neither confirmed nor dismissed — count
            # them on their own rather than letting the else sweep them into FP.
            if finding["verdict"] == "true_positive":
                tp_count += 1
            elif finding["verdict"] == VERDICT_UNVERIFIED:
                unverified_count += 1
            else:
                fp_count += 1
    return {
        "files_scanned": len(file_results),
        "tp_count": tp_count,
        "fp_count": fp_count,
        "unverified_count": unverified_count,
        "by_owasp_category": by_owasp,
        "chunk_errors": sum(len(r.get("chunk_errors") or []) for r in file_results),
    }


def _batchable_text(repo_root: Path, rel_path: str) -> Optional[str]:
    """The file's text when it can join a deep-scan batch: readable, small,
    one chunk, and something scan_file would actually review."""
    text = _read_text(repo_root, rel_path)
    if text is None or not text.strip() or len(text) > BATCH_FILE_MAX_CHARS:
        return None
    if is_non_analyzable_file(repo_root, rel_path, text):
        return None
    if len(chunk_file(text, lang_for_path(rel_path))) != 1:
        return None
    return text


def scan_deep_files(
    *,
    module_plan: Dict[str, Any],
    repo_root: Path,
    rules: List[RegexRule],
    active_frameworks: Optional[Set[str]] = None,
    dependency_index: Optional[Dict[str, List[Optional[str]]]] = None,
    priority_rule_ids: Optional[Set[str]] = None,
    stack_context: str = "",
    usage: Optional[Dict[str, Any]] = None,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    findings_writer: Optional[Callable[[str, List[Dict[str, Any]]], None]] = None,
    on_file_start: Optional[Callable[[int, int, str], None]] = None,
    on_file: Optional[Callable[[Dict[str, Any]], None]] = None,
    call_llm_fn: Callable[..., str] = call_llm,
    file_workers: int = DEFAULT_FILE_WORKERS,
    chunk_workers: int = DEFAULT_CHUNK_WORKERS,
    entries: Optional[List[Dict[str, Any]]] = None,
    suppress_no_cwe: bool = True,
    suppress_http_findings: bool = False,
    suppress_low_confidence_false_positives: bool = False,
    batch_small_files: bool = True,
    occurrence_validators: bool = True,
) -> Dict[str, Any]:
    """LLM-primary scan of every CRITICAL / HIGH file — no regex gate. MEDIUM
    and LOW (and, past DEEP_SCAN_FILE_CAP, overflow CRITICAL/HIGH) are handled
    by `scan_triage_files`.

    Files and the chunks within them run concurrently, bounded globally by
    MAX_INFLIGHT_LLM_CALLS. `findings_writer(file_path, findings)` is called
    once per file (TP and FP together). Pass the shared scan `usage` dict so
    the $2 Bedrock cutoff applies across calls.

    `entries`, when given, is the exact working set (already resolved by the
    caller, e.g. via `files_for_paths`) and `module_plan`'s own files are
    ignored; when omitted, the working set is derived from `module_plan` via
    `files_for_risk_levels(module_plan, LLM_RISK_LEVELS)` as before.

    `batch_small_files` reviews small files several per call when their
    language's system prompt isn't served from the prompt cache (see
    BATCH_FILE_MAX_CHARS); a failed batch falls back to one call per file.
    """
    critical_files = entries if entries is not None else files_for_risk_levels(module_plan, LLM_RISK_LEVELS)
    total = len(critical_files)

    prompt_cache: Dict[Optional[str], Tuple[List[Dict[str, Any]], str]] = {}
    cache_lock = threading.Lock()

    def _prompt_parts(path: str) -> Tuple[List[Dict[str, Any]], str]:
        lang = lang_for_path(path)
        with cache_lock:
            cached = prompt_cache.get(lang)
            if cached is None:
                catalog = trim_catalog(rules_for_prompt(
            rules, lang, active_frameworks,
            dependency_index=dependency_index, priority_rule_ids=priority_rule_ids,
        ))
                cached = (catalog, build_system_prompt(catalog, stack_context))
                prompt_cache[lang] = cached
        return cached

    results: List[Optional[Dict[str, Any]]] = [None] * total

    def _run(indexed: Tuple[int, Dict[str, Any]]) -> None:
        position, entry = indexed
        path = entry["path"]
        if on_file_start is not None:
            with _CALLBACK_LOCK:
                on_file_start(position + 1, total, path)
        catalog, system_prompt = _prompt_parts(path)
        result = scan_file(
            repo_root=repo_root, rel_path=path, rules=rules,
            active_frameworks=active_frameworks,
            dependency_index=dependency_index, priority_rule_ids=priority_rule_ids,
            stack_context=stack_context,
            usage=usage, llm_provider=llm_provider, llm_model=llm_model,
            call_llm_fn=call_llm_fn, on_chunk_start=_log_chunk_start,
            chunk_workers=chunk_workers, catalog=catalog,
            system_prompt=system_prompt, llm_step="scan_deep_files",
            suppress_no_cwe=suppress_no_cwe, suppress_http_findings=suppress_http_findings,
            suppress_low_confidence_false_positives=suppress_low_confidence_false_positives,
            occurrence_validators=occurrence_validators,
        )
        results[position] = result
        with _CALLBACK_LOCK:
            if findings_writer is not None:
                findings_writer(path, result["findings"])
            if on_file is not None:
                on_file(result)

    def _run_batch(batch: List[Tuple[int, str, str]]) -> None:
        catalog, system_prompt = _prompt_parts(batch[0][1])
        if on_file_start is not None:
            with _CALLBACK_LOCK:
                for position, path, _text in batch:
                    on_file_start(position + 1, total, path)
        print(f"  LLM batch of {len(batch)} small file(s): "
              + ", ".join(p.rsplit("/", 1)[-1] for _pos, p, _t in batch) + "…", flush=True)
        batch_results = scan_file_batch(
            files=[(path, text) for _pos, path, text in batch],
            catalog=catalog, system_prompt=system_prompt,
            usage=usage, llm_provider=llm_provider, llm_model=llm_model,
            call_llm_fn=call_llm_fn, llm_step="scan_deep_files",
            suppress_no_cwe=suppress_no_cwe, suppress_http_findings=suppress_http_findings,
            suppress_low_confidence_false_positives=suppress_low_confidence_false_positives,
            occurrence_validators=occurrence_validators,
        )
        if batch_results is None:
            for position, path, _text in batch:
                _run((position, {"path": path}))
            return
        for (position, path, _text), result in zip(batch, batch_results):
            results[position] = result
            with _CALLBACK_LOCK:
                if findings_writer is not None:
                    findings_writer(path, result["findings"])
                if on_file is not None:
                    on_file(result)

    indexed_files = list(enumerate(critical_files))
    units: List[Callable[[], None]] = []
    small_by_lang: Dict[Optional[str], List[Tuple[int, str, str]]] = {}
    for position, entry in indexed_files:
        path = entry["path"]
        text = _batchable_text(repo_root, path) if batch_small_files else None
        if text is not None:
            _catalog, system_prompt = _prompt_parts(path)
            if not system_prompt_is_cached(system_prompt, llm_provider, llm_model):
                small_by_lang.setdefault(lang_for_path(path), []).append((position, path, text))
                continue
        units.append(lambda item=(position, entry): _run(item))
    for small in small_by_lang.values():
        for batch in plan_deep_scan_batches(small):
            if len(batch) == 1:
                position, path, _text = batch[0]
                units.append(lambda item=(position, critical_files[position]): _run(item))
            else:
                units.append(lambda b=batch: _run_batch(b))

    if len(units) > 1 and file_workers > 1:
        with ThreadPoolExecutor(max_workers=min(file_workers, len(units))) as pool:
            list(pool.map(lambda unit: unit(), units))
    else:
        for unit in units:
            unit()

    final = [r for r in results if r is not None]
    return {
        "files_scanned": len(final),
        "tp_count": sum(r["tp_count"] for r in final),
        "fp_count": sum(r["fp_count"] for r in final),
        "unverified_count": sum(r.get("unverified_count") or 0 for r in final),
        "chunk_errors": sum(len(r.get("chunk_errors") or []) for r in final),
        "files": final,
    }


# --- MEDIUM/LOW tier: regex first, then LLM triage of the hits only ---------

_TRIAGE_SYSTEM = (
    "You triage regex-scanner hits. You do not hunt for new issues.\n"
    "Each candidate has an id (c1, c2, ...); its line is marked `<-- c<n>` in the "
    "numbered source excerpts. For every candidate id decide true_positive or "
    "false_positive.\n"
    "A hit is a false_positive when the match is a test fixture, placeholder, "
    "comment, sample data, or otherwise not a real vulnerability.\n"
    "Respond with the JSON object described under Output format only. No prose, "
    "no markdown fences."
)

_TRIAGE_RESPONSE_SCHEMA = """Output format — one JSON object, exactly one decision per candidate id:
{"decisions": [{
  "id": "<candidate id, e.g. c1>",
  "verdict": "true_positive" | "false_positive",
  "confidence": <0.0-1.0, how sure you are this is exploitable>,
  "verdict_reason": "<required, at most 2 sentences>",
  "severity": "<optional CRITICAL|HIGH|MEDIUM|LOW — only to correct the rule's default>",
  "ai_fix": "<at most 2 sentences; only when verdict is true_positive>"
}]}"""

# Excerpt lines longer than this are cut — the per-window char cap the old
# ±10-line blocks had (SNIPPET_MAX_CHARS) no longer applies once windows merge.
TRIAGE_LINE_MAX_CHARS = 400
BUDGET_EXHAUSTED_REASON = (
    "The LLM spend cutoff was reached before this part of the file was reviewed; "
    "this is a regex match that nobody has reviewed yet."
)
TRIAGE_NO_DECISION_REASON = (
    "LLM triage returned no usable decision for this candidate; it is a regex "
    "match that nobody has reviewed yet."
)


def _hit_matches_finding(finding: Dict[str, Any], hits: Sequence[Dict[str, Any]]) -> bool:
    rid = finding.get("rule_id")
    line = finding.get("line")
    if not rid or line is None:
        return False
    for hit in hits:
        if hit.get("rule") != rid:
            continue
        if abs(int(hit.get("line") or 0) - int(line)) <= CONTEXT_LINES_BEFORE:
            return True
    return False


def triage_candidates(hits: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Regex hits as triage candidates: repeat (rule, line) hits collapse, and
    each survivor gets a stable short id (c1, c2, ...) in hit order."""
    out: List[Dict[str, Any]] = []
    seen: Set[Tuple[Optional[str], int]] = set()
    for hit in hits:
        rule_id = hit.get("rule")
        line = int(hit.get("line") or 1)
        if (rule_id, line) in seen:
            continue
        seen.add((rule_id, line))
        out.append({
            "id": f"c{len(out) + 1}",
            "rule_id": rule_id,
            "line": line,
            "matched_text": (hit.get("matched_text") or "").strip(),
            "severity": hit.get("severity"),
            "col_start": hit.get("col_start"),
            "col_end": hit.get("col_end"),
        })
    return out


# A construct repeated many times in one file (102 identical hits in a legacy
# helper) is triaged once: one candidate carrying the occurrence count and the
# excerpts of its first few occurrences, with the verdict applied to all.
TRIAGE_GROUP_WINDOWS = 3


def group_triage_candidates(
    candidates: Sequence[Dict[str, Any]], rules_by_id: Dict[str, RegexRule],
) -> List[Dict[str, Any]]:
    """Collapse candidates that share a group key (group_key_for_finding — the
    same key the report groups on) into one representative each, renumbered
    c1..cn, with every member kept under "members"."""
    groups: Dict[tuple, List[Dict[str, Any]]] = {}
    for cand in candidates:
        rule = rules_by_id.get(cand.get("rule_id") or "")
        key = group_key_for_finding({
            "rule_id": cand.get("rule_id"), "matched_text": cand.get("matched_text"),
            "group_by_rule": bool(rule and rule.group_by_rule),
        })
        groups.setdefault(key, []).append(cand)
    out: List[Dict[str, Any]] = []
    for members in groups.values():
        rep = dict(members[0])
        rep["id"] = f"c{len(out) + 1}"
        rep["members"] = list(members)
        out.append(rep)
    return out


def merged_context_windows(
    line_numbers: Sequence[int],
    total_lines: int,
    *,
    before: int = CONTEXT_LINES_BEFORE,
    after: int = CONTEXT_LINES_AFTER,
) -> List[Tuple[int, int]]:
    """±before/after windows around each line, with overlapping or adjacent
    windows merged — so a line near several hits is sent once, not per hit."""
    spans = sorted(
        (max(1, n - before), min(max(total_lines, 1), n + after)) for n in line_numbers
    )
    merged: List[List[int]] = []
    for lo, hi in spans:
        if merged and lo <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])
    return [(lo, hi) for lo, hi in merged]


def _triage_prompts_for_candidates(
    *,
    file_path: str,
    source_text: str,
    candidates: Sequence[Dict[str, Any]],
    rules_by_id: Dict[str, RegexRule],
    stack_context: str = "",
) -> Tuple[str, str]:
    lines = source_text.splitlines()
    rule_lines: List[str] = []
    seen_rules: Set[str] = set()
    for cand in candidates:
        rid = cand.get("rule_id") or ""
        if rid in seen_rules:
            continue
        seen_rules.add(rid)
        rule = rules_by_id.get(rid)
        title = (rule.title if rule else rid) or "unknown"
        desc = (rule.description if rule else "") or ""
        rule_lines.append(
            f"- {rid} | {(rule.cwe if rule else '') or '-'} | "
            f"{(rule.severity if rule else cand.get('severity')) or 'LOW'} | "
            f"{title}{': ' + desc if desc and desc != title else ''}"
        )
    def _cand_line(c: Dict[str, Any]) -> str:
        members = c.get("members") or [c]
        where = f"line {c['line']}"
        if len(members) > 1:
            shown = ", ".join(str(m["line"]) for m in members[:TRIAGE_GROUP_WINDOWS])
            more = "" if len(members) <= TRIAGE_GROUP_WINDOWS else ", …"
            where = (f"{len(members)} occurrences of the same match in this file "
                     f"(lines {shown}{more}; your verdict covers only the occurrences shown here)")
        return (f"{c['id']} | {c['rule_id']} | {where} | matched: "
                + json.dumps(c["matched_text"][:200], ensure_ascii=False))

    cand_lines = [_cand_line(c) for c in candidates]
    markers: Dict[int, List[str]] = {}
    shown_lines: List[int] = []
    for c in candidates:
        for m in (c.get("members") or [c])[:TRIAGE_GROUP_WINDOWS]:
            markers.setdefault(int(m["line"]), []).append(c["id"])
            shown_lines.append(int(m["line"]))
    excerpts: List[str] = []
    for lo, hi in merged_context_windows(shown_lines, len(lines)):
        block = [f"--- lines {lo}-{hi} ---"]
        for n in range(lo, hi + 1):
            text = lines[n - 1] if n - 1 < len(lines) else ""
            if len(text) > TRIAGE_LINE_MAX_CHARS:
                text = text[:TRIAGE_LINE_MAX_CHARS] + "…"
            mark = f"  <-- {', '.join(markers[n])}" if n in markers else ""
            block.append(f"{n}: {text}{mark}")
        excerpts.append("\n".join(block))
    system = (
        f"{_TRIAGE_SYSTEM}\n\n{_TRIAGE_RESPONSE_SCHEMA}\n\n"
        f"Tech stack: {stack_context or 'unknown'}"
    )
    user = (
        f"File: {file_path}\n\n"
        "Rules (id | CWE | severity | title: description):\n"
        + "\n".join(rule_lines) + "\n\n"
        "Candidates (triage these only; do not add other findings):\n"
        + "\n".join(cand_lines) + "\n\n"
        "Source excerpts:\n" + "\n\n".join(excerpts) + "\n"
    )
    return system, user


def build_triage_prompts(
    *,
    file_path: str,
    source_text: str,
    hits: List[Dict[str, Any]],
    rules_by_id: Dict[str, RegexRule],
    stack_context: str = "",
) -> Tuple[str, str]:
    """System + user prompts for regex-hit triage (no extra findings).

    Carries only the hit candidates and merged context windows around them —
    the full file body is deliberately never included. Rule descriptions are
    listed once per rule, not once per hit."""
    return _triage_prompts_for_candidates(
        file_path=file_path, source_text=source_text,
        candidates=triage_candidates(hits), rules_by_id=rules_by_id,
        stack_context=stack_context,
    )


def resolve_triage_decisions(
    items: Sequence[Any],
    candidates: Sequence[Dict[str, Any]],
    *,
    rejected: Optional[Dict[str, Tuple[str, Any]]] = None,
) -> Dict[str, Dict[str, Any]]:
    """{candidate id: decision item} for every candidate the response actually
    decided. Items are matched by id; an item without a usable id (older
    array-of-findings shape, or a model ignoring the schema) is matched to the
    nearest undecided candidate of the same rule within the context window.
    Items matching no candidate (invented findings) are ignored, and so are
    items with no usable verdict (`parse_verdict`): those candidates stay
    undecided. When `rejected` is given, an unusable verdict on an item matched
    by id is recorded there as `{candidate id: (reason, raw verdict)}`."""
    by_id = {c["id"]: c for c in candidates}
    decided: Dict[str, Dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        verdict, reason = parse_verdict(item.get("verdict"))
        if verdict not in ("true_positive", "false_positive"):
            cid = str(item.get("id") or "").strip().lower()
            if rejected is not None and cid in by_id:
                rejected.setdefault(cid, (reason or "evidence_missing", item.get("verdict")))
            continue
        cid = str(item.get("id") or "").strip().lower()
        if cid in by_id:
            decided.setdefault(cid, item)
            continue
        rule_id = item.get("rule_id") or item.get("rule")
        try:
            line = int(item.get("line"))
        except (TypeError, ValueError):
            continue
        best: Optional[Dict[str, Any]] = None
        for cand in candidates:
            if cand["id"] in decided or cand["rule_id"] != rule_id:
                continue
            distance = abs(int(cand["line"]) - line)
            if distance <= CONTEXT_LINES_BEFORE and (
                best is None or distance < abs(int(best["line"]) - line)
            ):
                best = cand
        if best is not None:
            decided[best["id"]] = item
    return decided


def _triage_finding(
    cand: Dict[str, Any],
    item: Optional[Dict[str, Any]],
    *,
    file_path: str,
    source_text: str,
    rules_by_id: Dict[str, RegexRule],
    unresolved_reason: str = "llm_missing_verdict",
    raw_verdict: Any = None,
) -> Dict[str, Any]:
    """Build the finding locally from the candidate and rule; the model only
    contributes the decision fields. `unresolved_reason` (and the model's
    `raw_verdict`, when it gave an unusable one) apply only when there is no
    decision (`item is None`)."""
    rule = rules_by_id.get(cand.get("rule_id") or "")
    cwe = ((rule.cwe if rule else "") or "").strip() or None
    severity = str((rule.severity if rule else cand.get("severity")) or "LOW").upper()
    base = {
        "rule_id": cand["rule_id"],
        "title": ((rule.title if rule else None) or cand["rule_id"] or "Regex match")[:500],
        "cwe": cwe,
        "owasp_category": (rule.owasp if rule else "") or owasp_for_rule(cwe, None),
        "file_path": file_path,
        "line": int(cand["line"]),
        "source": "",
        "sink": "",
        "data_flow": "",
        "matched_text": cand["matched_text"][:500],
        "group_by_rule": bool(rule.group_by_rule) if rule else False,
        "derived": bool(rule.derived) if rule else False,
        "wrapper": rule.wrapper if rule else None,
        "issue_class": rule.issue_class if rule else DEFAULT_ISSUE_CLASS,
        "decision_stage": "triage_llm",
        "kind": "regex",
        "col_start": cand.get("col_start"),
        "col_end": cand.get("col_end"),
    }
    if item is None:
        return {
            **base,
            "severity": severity,
            "snippet": build_code_context(source_text, int(cand["line"]), cand["matched_text"]),
            "verdict": VERDICT_UNVERIFIED,
            "unresolved_reason": unresolved_reason,
            "verdict_reason": (
                _unresolved_verdict_reason(raw_verdict, unresolved_reason)
                if unresolved_reason == "llm_unrecognised_verdict"
                else TRIAGE_NO_DECISION_REASON
            ),
            "confidence": None,
            "ai_fix": None,
        }
    verdict = parse_verdict(item.get("verdict"))[0]
    if verdict not in ("true_positive", "false_positive"):
        verdict = VERDICT_UNVERIFIED
    override = str(item.get("severity") or "").strip().upper()
    ai_fix = item.get("ai_fix")
    return {
        **base,
        "severity": override if override in _VALID_SEVERITIES else severity,
        # The flagged line itself; finalize_findings swaps in the real context.
        "snippet": cand["matched_text"],
        "verdict": verdict,
        "verdict_reason": (
            str(item.get("verdict_reason") or item.get("reason") or "").strip()
            or "No reason provided by the model."
        ),
        "confidence": _normalize_confidence(item.get("confidence"), verdict),
        "ai_fix": str(ai_fix).strip() if verdict == "true_positive" and ai_fix else None,
    }


def triage_regex_hits(
    *,
    file_path: str,
    source_text: str,
    hits: List[Dict[str, Any]],
    rules: List[RegexRule],
    stack_context: str = "",
    usage: Optional[Dict[str, Any]] = None,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    call_llm_fn: Callable[..., str] = call_llm,
    occurrence_validators: bool = True,
) -> Dict[str, Any]:
    """One LLM call to TP/FP-triage the regex hits in a MEDIUM/LOW-risk file.

    Hits that repeat one construct (group_triage_candidates) are asked about
    once and the verdict is applied to every occurrence. Every candidate ends
    up with exactly one outcome: a model decision, or — when the response
    omitted it, was unparseable, or the call failed — `unverified`.
    Candidates the model left out get one follow-up call carrying only their
    own excerpts before falling back to unverified."""
    if not hits:
        return {
            "file_path": file_path, "chunks": 0, "findings": [],
            "tp_count": 0, "fp_count": 0, "read_error": False, "chunk_errors": [],
        }

    rules_by_id = {rule.id: rule for rule in rules}
    candidates = group_triage_candidates(triage_candidates(hits), rules_by_id)
    errors: List[str] = []
    call_failure: List[str] = []  # reason of the last call that raised, if any
    rejected: Dict[str, Tuple[str, Any]] = {}  # candidate id -> (reason, raw verdict)
    answer_cache_hits: List[bool] = []  # one per call that returned an answer

    def _ask(subset: Sequence[Dict[str, Any]]) -> Tuple[Dict[str, Dict[str, Any]], bool]:
        """(decisions, call_raised)."""
        system, user = _triage_prompts_for_candidates(
            file_path=file_path, source_text=source_text, candidates=subset,
            rules_by_id=rules_by_id, stack_context=stack_context,
        )
        try:
            with _INFLIGHT:
                raw_text = call_llm_fn(
                    system, user,
                    max_tokens=4096, temperature=0.0,
                    usage=usage, step="scan_triage_files",
                    provider=llm_provider, model=llm_model, json_mode=True,
                )
        except Exception as exc:  # one bad file must not kill the tier
            errors.append(f"{type(exc).__name__}: {exc}")
            call_failure.append(unresolved_reason_for_exception(exc))
            return {}, True
        answer_cache_hits.append(last_call_was_cache_hit())
        items, err = parse_llm_json_array(raw_text)
        if err and not items:
            errors.append(err)
        return resolve_triage_decisions(items, subset, rejected=rejected), False

    decided, raised = _ask(candidates)
    missing = [c for c in candidates if c["id"] not in decided]
    if missing and not raised:
        # Unparseable, partial, or empty answer: ask again for just the gaps,
        # carrying only their excerpts. A call that raised is not retried
        # here — call_llm already retried the transport.
        more, _raised = _ask(missing)
        decided.update(more)
        missing = [c for c in candidates if c["id"] not in decided]
    if missing:
        errors.append(f"{len(missing)} candidate(s) left unverified (no decision)")

    reviewed = []
    not_shown: List[Dict[str, Any]] = []
    for c in candidates:
        if c["id"] not in decided:
            continue
        shown_members = c["members"][:TRIAGE_GROUP_WINDOWS]
        reviewed.extend(
            _triage_finding(m, decided[c["id"]], file_path=file_path,
                            source_text=source_text, rules_by_id=rules_by_id)
            for m in shown_members
        )
        # A verdict is for the occurrences the model was shown. The others of a
        # repeated match are not given it: they stay unverified, not_in_sample.
        for m in c["members"][TRIAGE_GROUP_WINDOWS:]:
            skipped = _triage_finding(
                m, None, file_path=file_path, source_text=source_text,
                rules_by_id=rules_by_id, unresolved_reason="not_in_sample",
            )
            skipped["verdict_reason"] = (
                f"Not reviewed: only the first {TRIAGE_GROUP_WINDOWS} of {len(c['members'])} "
                f"identical matches in this file were shown for review."
            )
            not_shown.append(skipped)
    reviewed = [f for f in reviewed if f["verdict"] != VERDICT_UNVERIFIED]
    merged = dedupe_and_finalize(
        reviewed, source_text, file_path=file_path, usage=usage,
        occurrence_validators=occurrence_validators,
    )
    replayed = bool(answer_cache_hits) and all(answer_cache_hits)
    for finding in merged:
        finding["result_cache_hit"] = replayed
    # Undecided candidates bypass suppression, exactly like regex-only
    # findings: no one has judged them, so nothing may be dropped on a guess.
    unverified = []
    for c in missing:
        if c["id"] in rejected:
            undecided_reason, raw_verdict = rejected[c["id"]]
        else:
            undecided_reason = call_failure[-1] if call_failure else "llm_missing_verdict"
            raw_verdict = None
        _record_verdict_problem(usage, "scan_triage_files", undecided_reason)
        unverified.extend(
            _triage_finding(m, None, file_path=file_path, source_text=source_text,
                            rules_by_id=rules_by_id, unresolved_reason=undecided_reason,
                            raw_verdict=raw_verdict)
            for m in c["members"]
        )
    unverified.extend(not_shown)
    findings = merged + unverified
    for finding in findings:
        finding["kind"] = "regex"
    tp_count = sum(1 for f in findings if f["verdict"] == "true_positive")
    fp_count = sum(1 for f in findings if f["verdict"] == "false_positive")
    return {
        "file_path": file_path,
        "chunks": 1,
        "findings": findings,
        "tp_count": tp_count,
        "fp_count": fp_count,
        "unverified_count": len(unverified),
        "read_error": False,
        "chunk_errors": errors,
    }


def findings_from_hits(
    *,
    file_path: str,
    source_text: str,
    hits: List[Dict[str, Any]],
    rules_by_id: Dict[str, RegexRule],
    usage: Optional[Dict[str, Any]] = None,
    occurrence_validators: bool = True,
) -> List[Dict[str, Any]]:
    """Turn regex hits straight into findings — no LLM, no verdict guessing.

    Every finding is recorded as `unverified`: the pattern matched, and nobody
    has judged whether it is exploitable. That is deliberately not the same as
    `true_positive` (which would let regex noise masquerade as confirmed
    vulnerabilities) nor `false_positive` (which would hide real ones).

    Repeat hits of the same rule on the same line collapse; two different rules
    on one line stay separate, since they describe different problems.
    """
    out: List[Dict[str, Any]] = []
    seen: Set[Tuple[Optional[str], int]] = set()
    for hit in hits:
        rule_id = hit.get("rule")
        line = int(hit.get("line") or 1)
        if (rule_id, line) in seen:
            continue
        seen.add((rule_id, line))
        rule = rules_by_id.get(rule_id or "")
        matched = (hit.get("matched_text") or "").strip()
        out.append({
            "rule_id": rule_id,
            "title": ((rule.title if rule else None) or rule_id or "Regex match")[:500],
            "severity": (rule.severity if rule else hit.get("severity")) or "LOW",
            "cwe": (rule.cwe if rule else "") or "",
            "owasp_category": (rule.owasp if rule else "") or owasp_for_rule(rule_id or "", ""),
            "line": line,
            "snippet": build_code_context(source_text, line, matched),
            # The bare matched construct, kept separate from the surrounding
            # context window so findings can be grouped by what actually
            # matched rather than by 21 lines of incidental neighbouring code.
            "matched_text": matched[:500],
            "group_by_rule": bool(rule.group_by_rule) if rule else False,
            "derived": bool(rule.derived) if rule else False,
            "wrapper": rule.wrapper if rule else None,
            "issue_class": (rule.issue_class if rule else DEFAULT_ISSUE_CLASS),
            "decision_stage": "triage_regex",
            "verdict": VERDICT_UNVERIFIED,
            "unresolved_reason": "not_reviewed_regex",
            "verdict_reason": UNVERIFIED_REASON,
            "kind": "regex",
            "confidence": None,
            "col_start": hit.get("col_start"),
            "col_end": hit.get("col_end"),
        })
    # Occurrence facts, then the validators: a regex hit one of them proves is
    # not what its rule says is still written, as a false positive with the
    # proof — the report shows the scanner looked at it.
    prepare_findings(
        out, source_text, file_path=file_path, usage=usage, validators=occurrence_validators,
    )
    return out


def scan_triage_files(
    *,
    module_plan: Dict[str, Any],
    repo_root: Path,
    rules: List[RegexRule],
    active_frameworks: Optional[Set[str]] = None,
    dependency_index: Optional[Dict[str, List[Optional[str]]]] = None,
    priority_rule_ids: Optional[Set[str]] = None,
    stack_context: str = "",
    usage: Optional[Dict[str, Any]] = None,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    findings_writer: Optional[Callable[[str, List[Dict[str, Any]]], None]] = None,
    on_file_start: Optional[Callable[[int, int, str], None]] = None,
    on_file: Optional[Callable[[Dict[str, Any]], None]] = None,
    call_llm_fn: Callable[..., str] = call_llm,
    file_workers: int = DEFAULT_FILE_WORKERS,
    entries: Optional[List[Dict[str, Any]]] = None,
    triage_mode: str = DEFAULT_TRIAGE_MODE,
    rules_for_path: Optional[Callable[[str], List[RegexRule]]] = None,
    on_file_done: Optional[Callable[[int, Dict[str, Any]], None]] = None,
    regex_processes: Optional[bool] = None,
    occurrence_validators: bool = True,
) -> Dict[str, Any]:
    """Regex-scan every MEDIUM/LOW-risk file (plus any CRITICAL/HIGH overflow
    the caller routes here past DEEP_SCAN_FILE_CAP).

    Zero-hit files are skipped entirely, and machine-generated files that do
    have hits are skipped too (their findings are not actionable — you would
    fix the generator or the schema, never the output).

    What happens to the remaining hits depends on `triage_mode`:

    * `regex_only` (default) — hits become findings directly, marked
      `unverified`. No LLM call at all; this is what makes a multi-thousand-file
      repo finish in minutes instead of hours.
    * `llm_triage` — hits plus their context windows go to the LLM for a
      true/false-positive ruling. More precise, far more expensive.

    `entries`, when given, is the exact working set (already resolved by the
    caller) and `module_plan`'s own files are ignored — this is what lets an
    overflow CRITICAL/HIGH entry (risk_level still "CRITICAL"/"HIGH") run
    through this triage path despite failing the TRIAGE_RISK_LEVELS check;
    when omitted, the working set is derived from `module_plan` as before.

    `rules_for_path` (pipeline/rg_prefilter.py) narrows the rules run on each
    file to those ripgrep found a required literal for; a file left with no
    rules is never read. Python stays the authority on every hit.

    `on_file_done(position, result)` fires once per entry, whatever happened
    to it (callers track per-batch completion with it). `regex_processes`
    runs the regex pass in worker processes — None means "when there are at
    least regex_scan.PROCESS_POOL_MIN_FILES files"; the findings are the same
    either way.
    """
    triage_files = entries if entries is not None else files_for_risk_levels(module_plan, TRIAGE_RISK_LEVELS)
    total = len(triage_files)
    results: List[Optional[Dict[str, Any]]] = [None] * total
    rules_by_id = {rule.id: rule for rule in rules}

    prescanned: Dict[str, Dict[str, Any]] = {}
    if regex_processes or (regex_processes is None and total >= PROCESS_POOL_MIN_FILES):
        jobs = []
        for entry in triage_files:
            path = entry["path"]
            file_rules = rules_for_path(path) if rules_for_path is not None else rules
            if not file_rules:
                continue  # prefiltered out; _run_one records it without reading
            rule_ids = None if file_rules is rules else tuple(r.id for r in file_rules)
            jobs.append((path, entry.get("module", "(root)"), entry.get("lang") or lang_for_path(path), rule_ids))
        prescanned = scan_files_in_processes(
            jobs, repo_root=repo_root, rules=rules,
            active_frameworks=active_frameworks, dependency_index=dependency_index,
        ) or {}

    def _run(indexed: Tuple[int, Dict[str, Any]]) -> None:
        try:
            _run_one(indexed)
        finally:
            if on_file_done is not None:
                with _CALLBACK_LOCK:
                    on_file_done(indexed[0], results[indexed[0]] or {})

    def _run_one(indexed: Tuple[int, Dict[str, Any]]) -> None:
        position, entry = indexed
        path = entry["path"]
        if on_file_start is not None:
            with _CALLBACK_LOCK:
                on_file_start(position + 1, total, path)
        lang = entry.get("lang") or lang_for_path(path)
        file_rules = rules_for_path(path) if rules_for_path is not None else rules
        if not file_rules:
            results[position] = {
                "file_path": path, "chunks": 0, "findings": [],
                "tp_count": 0, "fp_count": 0, "read_error": False,
                "skipped_no_hits": True, "prefiltered": True, "chunk_errors": [],
            }
            return
        scanned = prescanned.get(path) or scan_one_file(
            repo_root, path, entry.get("module", "(root)"), file_rules,
            file_lang=lang, active_frameworks=active_frameworks,
            dependency_index=dependency_index,
        )
        if scanned.get("read_error") or not scanned.get("hits"):
            results[position] = {
                "file_path": path, "chunks": 0, "findings": [],
                "tp_count": 0, "fp_count": 0, "read_error": bool(scanned.get("read_error")),
                "skipped_no_hits": not scanned.get("hits"),
                "chunk_errors": [],
            }
            return
        text = _read_text(repo_root, path) or ""
        # Checked only for files that already have hits: the text is read here
        # anyway, and a generated file with no hits was free regardless.
        if looks_generated(text):
            results[position] = {
                "file_path": path, "chunks": 0, "findings": [],
                "tp_count": 0, "fp_count": 0, "read_error": False,
                "skipped_generated": True, "chunk_errors": [],
            }
            return
        if looks_vendored_or_minified(path, text):
            results[position] = {
                "file_path": path, "chunks": 0, "findings": [],
                "tp_count": 0, "fp_count": 0, "read_error": False,
                "skipped_vendored": True, "chunk_errors": [],
            }
            return

        if triage_mode == TRIAGE_MODE_REGEX_ONLY:
            findings = findings_from_hits(
                file_path=path, source_text=text,
                hits=scanned["hits"], rules_by_id=rules_by_id,
                usage=usage, occurrence_validators=occurrence_validators,
            )
            # Deliberately NOT run through should_publish_finding: that gate
            # drops non-true_positive findings on noisy catalog rules, which
            # would delete every unverified finding here. It exists to suppress
            # findings an LLM invented; a regex hit is ground truth about what
            # matched, so the human reviewer gets to decide instead.
            result = {
                "file_path": path, "chunks": 0, "findings": findings,
                "tp_count": 0,
                "fp_count": sum(1 for f in findings if f.get("verdict") == "false_positive"),
                "unverified_count": sum(1 for f in findings if f.get("verdict") == VERDICT_UNVERIFIED),
                "read_error": False, "chunk_errors": [],
            }
        else:
            result = triage_regex_hits(
                file_path=path, source_text=text, hits=scanned["hits"],
                rules=rules, stack_context=stack_context, usage=usage,
                llm_provider=llm_provider, llm_model=llm_model,
                call_llm_fn=call_llm_fn, occurrence_validators=occurrence_validators,
            )
        results[position] = result
        with _CALLBACK_LOCK:
            if findings_writer is not None:
                findings_writer(path, result["findings"])
            if on_file is not None:
                on_file(result)

    indexed_files = list(enumerate(triage_files))
    if total > 1 and file_workers > 1:
        with ThreadPoolExecutor(max_workers=min(file_workers, total)) as pool:
            list(pool.map(_run, indexed_files))
    else:
        for item in indexed_files:
            _run(item)

    triaged = [
        r for r in results
        if r is not None
        and not r.get("skipped_no_hits")
        and not r.get("skipped_generated")
        and not r.get("skipped_vendored")
        and not r.get("read_error")
    ]
    return {
        "files_scanned": len(triaged),
        "files_regex_scanned": total,
        "files_skipped_generated": sum(
            1 for r in results if r is not None and r.get("skipped_generated")
        ),
        "files_skipped_vendored": sum(
            1 for r in results if r is not None and r.get("skipped_vendored")
        ),
        "tp_count": sum(r["tp_count"] for r in triaged),
        "fp_count": sum(r["fp_count"] for r in triaged),
        "unverified_count": sum(r.get("unverified_count") or 0 for r in triaged),
        "chunk_errors": sum(len(r.get("chunk_errors") or []) for r in triaged),
        "files": triaged,
    }


# --- grouped confirmation of unverified MEDIUM/LOW findings -----------------
#
# Used by node_confirm_triage_groups (sast_scan_agent.py) when triage_mode is
# regex_only: instead of one LLM call per file (the expensive llm_triage mode
# this deliberately avoids), unverified findings that share the same construct
# are grouped into one call, whose verdict is then applied to every member.
# Cost scales with unique-pattern count, not finding/file count — and, with
# groups_per_call > 1, further amortizes the per-call system-prompt overhead
# across several groups at once.
#
# group_key_for_finding mirrors app.services.scan_export._finding_group_key's
# regex branch (rule_id + normalized matched_text) on purpose, so confirmation
# collapses exactly what the UI already collapses into one row. Duplicated
# rather than imported: sast_engine has no dependency on the app package (see
# agent_bridge.py's lazy-import rationale). If scan_export._finding_group_key's
# regex branch changes, mirror the change here too.

# Grouped confirmation decides every member it shows (SAST-01-070). Each member
# gets an excerpt of its own code, up to a character budget per group; members
# the budget cannot show are never given a sibling's verdict — they stay
# unverified, `not_in_sample`.
GROUP_CONFIRM_MEMBER_CHAR_BUDGET = 16_000
GROUP_CONFIRM_WINDOW_LINES = 4
GROUP_CONFIRM_LINE_MAX_CHARS = 240
GROUP_CONFIRM_EVIDENCE_MEMBERS = 3
# Bounds on one call, so an answer stays short enough to come back quickly:
# at most this many occurrences shown per group, and per batched call.
GROUP_CONFIRM_MAX_SHOWN = 20
GROUP_CONFIRM_BATCH_MAX_SHOWN = 24
# Output tokens allowed per occurrence shown (a one-sentence reason).
GROUP_CONFIRM_TOKENS_PER_MEMBER = 90
CONFIRM_STEP = "group_confirm_triage_findings"

_GROUP_CONFIRM_SYSTEM = (
    "You confirm whether regex-matched code occurrences are real vulnerabilities. "
    "You are shown several occurrences of one pattern, each with an id (m1, m2, ...) "
    "and an excerpt of its own code. Decide EACH occurrence on its own code: "
    "occurrences of one pattern can differ in what they call, in what they pass to it, "
    "and in whether a value is a number or attacker-controlled text, and a verdict for "
    "one says nothing about another unless the code shown is the same.\n"
    "An occurrence is a false_positive when the match is a test fixture, placeholder, "
    "comment, sample data, a declaration rather than a call, or otherwise not a real "
    "vulnerability.\n"
    "Respond with the JSON object described under Output format only. No prose, "
    "no markdown fences."
)

_GROUP_RESPONSE_SCHEMA = """Output format — one JSON object with exactly one decision per occurrence shown:
{"decisions": [{
  "member": "<the occurrence id, e.g. m1>",
  "verdict": "true_positive" | "false_positive",
  "confidence": <0.0-1.0, how sure you are of this verdict (1.0 = certain), whichever verdict it is>,
  "verdict_reason": "<why this occurrence is/isn't a real issue — required, one short sentence>",
  "ai_fix": "<at most 2 sentences; only on the FIRST true_positive occurrence of a pattern, omitted on every other>"
}, ...]}"""


def group_key_for_finding(finding: Dict[str, Any]) -> tuple:
    """Same-issue key for unverified regex findings — mirrors
    app.services.scan_export._finding_group_key (minus its leading verdict).

    The last element is the occurrence's semantic signature (callee, receiver
    type, argument kinds — `occurrence_facts.semantic_signature`): members that
    differ in what they actually call, or in what they pass to it, are not one
    construct, so a verdict for one is never copied to the other. A rule with
    `group_by_rule` still collapses a varying matched text, but never across
    signatures. Members with no facts all share `unresolved` and group with
    each other only."""
    rule_id = str(finding.get("rule_id") or "").strip()
    matched = " ".join(str(finding.get("matched_text") or "").split())[:200]
    signature = semantic_signature(finding.get("facts"))
    if rule_id and rule_id.lower() != "llm-extra":
        if finding.get("group_by_rule"):
            return ("rule", rule_id, signature)
        return ("rule", rule_id, matched, signature)
    topic = re.sub(r"[^a-z0-9]+", " ", str(finding.get("title") or "").lower()).strip()
    topic = " ".join(topic.split()[:3])
    return ("topic", str(finding.get("cwe") or "").strip().upper(), topic, matched, signature)


def group_unverified_findings(
    file_results: List[Dict[str, Any]],
    *,
    severities: Set[str] = UNVERIFIED_FINDING_SEVERITIES,
) -> Dict[str, Any]:
    """Group unverified findings across `file_results` (the `files` list from
    `scan_triage_files`'s return value) by construct — no LLM call, no
    verdicts touched. This is the grouping step alone, so its output (group
    counts, top patterns by occurrence) can be reviewed before deciding how to
    spend LLM tokens confirming TP/FP.

    Only findings with `severity` in `severities` (default: every severity an
    unverified finding can carry — MEDIUM/LOW plus CRITICAL/HIGH overflow past
    DEEP_SCAN_FILE_CAP) and `verdict == unverified` are considered;
    already-confirmed findings are left out of the summary entirely.

    Returns:
      candidate_count / group_count — top-line numbers.
      groups — display-ready summaries (rule_id, matched_text, severity,
        owasp_category, occurrence_count, sample_files), sorted by
        occurrence_count descending so the biggest collapses show first.
      members_by_key / group_order — the raw grouping (group key -> member
        finding dicts, in first-seen order), so a caller that goes on to
        confirm these groups (e.g. group_confirm_unverified_findings) does
        not need to re-derive the grouping.
    """
    wanted_severities = {s.upper() for s in severities}
    candidates: List[Dict[str, Any]] = []
    for file_result in file_results:
        for finding in file_result.get("findings", []):
            if (
                finding.get("verdict") == VERDICT_UNVERIFIED
                and str(finding.get("severity") or "").upper() in wanted_severities
            ):
                # Regex and Joern-query findings are built per file and carry
                # no path of their own; confirmation needs it for the excerpt,
                # the occurrence list and the DB update key.
                if not finding.get("file_path") and file_result.get("file_path"):
                    finding["file_path"] = file_result["file_path"]
                candidates.append(finding)

    groups: Dict[tuple, List[Dict[str, Any]]] = {}
    group_order: List[tuple] = []
    constructs: Set[tuple] = set()  # the same grouping before the semantic split
    for finding in candidates:
        key = group_key_for_finding(finding)
        constructs.add(key[:-1])
        bucket = groups.setdefault(key, [])
        if not bucket:
            group_order.append(key)
        bucket.append(finding)

    summaries: List[Dict[str, Any]] = []
    for key in group_order:
        members = groups[key]
        representative = members[0]
        sample_files: List[str] = []
        seen: Set[str] = set()
        for m in members:
            p = m.get("file_path") or ""
            if p and p not in seen:
                seen.add(p)
                sample_files.append(p)
                if len(sample_files) >= 10:
                    break
        summaries.append({
            "rule_id": representative.get("rule_id"),
            "matched_text": representative.get("matched_text"),
            "severity": representative.get("severity"),
            "owasp_category": representative.get("owasp_category"),
            "occurrence_count": len(members),
            "sample_files": sample_files,
            "signature": key[-1],
        })
    summaries.sort(key=lambda g: g["occurrence_count"], reverse=True)

    return {
        "candidate_count": len(candidates),
        "group_count": len(group_order),
        "construct_count": len(constructs),
        "groups": summaries,
        "members_by_key": groups,
        "group_order": group_order,
    }


def _confirm_result_from_item(
    item: Dict[str, Any], *, usage: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    verdict, problem = parse_verdict(item.get("verdict"))
    if verdict not in ("true_positive", "false_positive"):
        # A missing, unrecognised or literally "unverified" verdict is not a
        # dismissal — leave the member unverified and say why.
        _record_verdict_problem(usage, CONFIRM_STEP, problem)
        raw = item.get("verdict")
        return {
            "verdict": VERDICT_UNVERIFIED, "confidence": None,
            "verdict_reason": "", "ai_fix": None,
            "error": (
                "missing verdict" if problem == "llm_missing_verdict"
                else f"unrecognised verdict: {' '.join(str(raw).split())[:VERDICT_REASON_MAX_CHARS]}"
            ),
            "unresolved_reason": problem or "evidence_missing",
        }
    confidence = _normalize_confidence(item.get("confidence"), verdict)
    reason = str(item.get("verdict_reason") or "").strip() or "No reason provided by the model."
    ai_fix = item.get("ai_fix")
    ai_fix = str(ai_fix).strip() if verdict == "true_positive" and ai_fix else None
    return {
        "verdict": verdict, "confidence": confidence,
        "verdict_reason": reason, "ai_fix": ai_fix, "error": None,
        "unresolved_reason": None,
    }


# A group entry is what the confirmer works on:
#   {"group_index": int, "members": [finding dicts, strongest evidence first],
#    "rule": RegexRule | None, "text_for": path -> source text}
# Members are addressed in prompts as m1..mN by position in `members`.

def _member_id(index: int) -> str:
    return f"m{index + 1}"


def _member_window(entry: Dict[str, Any], index: int) -> Tuple[int, int, List[str]]:
    member = entry["members"][index]
    lines = entry["text_for"](member.get("file_path") or "").splitlines()
    line = int(member.get("line") or 1)
    lo = max(1, line - GROUP_CONFIRM_WINDOW_LINES)
    hi = min(max(len(lines), 1), line + GROUP_CONFIRM_WINDOW_LINES)
    return lo, hi, lines


def _excerpt_signature(entry: Dict[str, Any], index: int) -> str:
    """The code around a member with line numbers and layout taken away: two
    members with the same one have nothing to tell them apart."""
    lo, hi, lines = _member_window(entry, index)
    return "\n".join(" ".join(lines[n - 1].split()) for n in range(lo, hi + 1) if n - 1 < len(lines))


def _variant_of(entry: Dict[str, Any]) -> Dict[int, List[int]]:
    """member index -> the indices of every member with identical code, itself
    included, in member order. Members are identical when they have the same
    semantic signature and the same normalized excerpt: nothing in the code tells
    them apart, so one decision is, verifiably, a decision for each. The first
    index of a variant is the one shown."""
    cached = entry.get("_variant_of")
    if cached is not None:
        return cached
    by_code: Dict[Tuple[str, str], List[int]] = {}
    for idx, member in enumerate(entry["members"]):
        key = (semantic_signature(member.get("facts")), _excerpt_signature(entry, idx))
        by_code.setdefault(key, []).append(idx)
    variant_of = {idx: variant for variant in by_code.values() for idx in variant}
    entry["_variant_of"] = variant_of
    return variant_of


def variant_count(entry: Dict[str, Any]) -> int:
    """How many distinct pieces of code a group holds: what confirming it costs."""
    return len({variant[0] for variant in _variant_of(entry).values()})


def _is_uniform(entry: Dict[str, Any]) -> bool:
    """Every member is identical code, so one decision is a decision for all."""
    members = entry["members"]
    return len(members) > 1 and len(_variant_of(entry)[0]) == len(members)


def _fact_summary(member: Dict[str, Any]) -> str:
    facts = member.get("facts") if isinstance(member.get("facts"), dict) else None
    call = (facts or {}).get("call")
    if not call:
        if facts and facts.get("is_declaration"):
            shape = "a stub" if facts.get("is_stub") else "an implementation"
            return f"declaration of {(facts.get('enclosing') or {}).get('method')} ({shape})"
        return ""
    kinds = ", ".join(a.get("kind", "unknown") for a in facts.get("args") or [])
    receiver = call.get("receiver_fqn") or call.get("receiver") or "?"
    return f"calls {call.get('callee')} on {receiver}; argument kinds: ({kinds})"


def _plan_members(
    entry: Dict[str, Any], indices: Sequence[int], budget: Optional[int] = None
) -> Tuple[List[int], List[int], bool]:
    """(shown, left over, uniform): one member per variant of identical code
    among `indices`, in order, as many as fit the character budget and
    `GROUP_CONFIRM_MAX_SHOWN` — always at least one. A shown member stands for
    every member of its variant; the left over are the members of variants not
    shown. `uniform` says the whole group is one variant."""
    if budget is None:
        budget = GROUP_CONFIRM_MEMBER_CHAR_BUDGET
    variant_of = _variant_of(entry)
    representatives: List[int] = []
    for idx in indices:
        first = variant_of[idx][0]
        if first not in representatives:
            representatives.append(first)
    shown: List[int] = []
    used = 0
    for idx in representatives:
        lo, hi, lines = _member_window(entry, idx)
        cost = 120 + sum(
            min(len(lines[n - 1]), GROUP_CONFIRM_LINE_MAX_CHARS) + 8
            for n in range(lo, hi + 1) if n - 1 < len(lines)
        )
        if shown and (used + cost > budget or len(shown) >= GROUP_CONFIRM_MAX_SHOWN):
            break
        shown.append(idx)
        used += cost
    covered = {member for idx in shown for member in variant_of[idx]}
    return shown, [i for i in indices if i not in covered], _is_uniform(entry)


def _render_members(entry: Dict[str, Any], shown: Sequence[int], uniform: bool) -> str:
    """The occurrences block of a prompt: one header line per member, then the
    code, windows of one file merged and each member's line marked."""
    members = entry["members"]
    lines_out: List[str] = []
    if uniform:
        lines_out.append(
            f"All {len(members)} occurrences are identical: the same code around the match and "
            f"the same resolved call. m1 stands for all of them; your decision for m1 is the "
            f"decision for every occurrence."
        )
    variant_of = _variant_of(entry)
    for idx in shown:
        m = members[idx]
        summary = _fact_summary(m)
        copies = len(variant_of[idx]) - 1
        lines_out.append(
            f"{_member_id(idx)} | {m.get('file_path')}:{m.get('line')}" + (f" | {summary}" if summary else "")
            + (f" | stands for {copies} more identical occurrence(s)" if copies and not uniform else "")
        )
    by_file: Dict[str, List[int]] = {}
    for idx in shown:
        by_file.setdefault(members[idx].get("file_path") or "", []).append(idx)
    for path, idxs in by_file.items():
        file_lines = entry["text_for"](path).splitlines()
        markers: Dict[int, List[str]] = {}
        for idx in idxs:
            markers.setdefault(int(members[idx].get("line") or 1), []).append(_member_id(idx))
        windows = merged_context_windows(
            list(markers), len(file_lines),
            before=GROUP_CONFIRM_WINDOW_LINES, after=GROUP_CONFIRM_WINDOW_LINES,
        )
        for lo, hi in windows:
            block = [f"--- {path} lines {lo}-{hi} ---"]
            for n in range(lo, hi + 1):
                text = file_lines[n - 1] if n - 1 < len(file_lines) else ""
                if len(text) > GROUP_CONFIRM_LINE_MAX_CHARS:
                    text = text[:GROUP_CONFIRM_LINE_MAX_CHARS] + "…"
                mark = f"  <-- {', '.join(markers[n])}" if n in markers else ""
                block.append(f"{n}: {text}{mark}")
            lines_out.append("\n".join(block))
    evidence = [
        f"Evidence for {_member_id(idx)}:\n" + reachability.render_evidence(members[idx]["reachability"])
        for idx in shown if members[idx].get("reachability")
    ][:GROUP_CONFIRM_EVIDENCE_MEMBERS]
    facts_block = render_deterministic_facts(
        [members[idx] for idx in shown], labels=[_member_id(idx) for idx in shown],
    )
    return "\n".join(lines_out) + (("\n\n" + "\n\n".join(evidence)) if evidence else "") + (
        ("\n\n" + facts_block) if facts_block else ""
    )


def _candidate_json(entry: Dict[str, Any]) -> Dict[str, Any]:
    members = entry["members"]
    representative = members[0]
    rule = entry["rule"]
    paths: List[str] = []
    for m in members:
        p = m.get("file_path") or ""
        if p and p not in paths:
            paths.append(p)
    shown = paths[:10]
    extra = len(paths) - len(shown)
    return {
        "rule_id": representative.get("rule_id"),
        "title": (rule.title if rule else representative.get("title")) or "",
        "description": (rule.description if rule else "") or "",
        "cwe": (rule.cwe if rule else representative.get("cwe")) or "",
        "severity": (rule.severity if rule else representative.get("severity")) or "LOW",
        "owasp": (rule.owasp if rule else representative.get("owasp_category")) or "",
        "matched_text": representative.get("matched_text") or "",
        "occurrence_count": len(members),
        "occurrence_files": ", ".join(shown) + (f", +{extra} more" if extra > 0 else ""),
    }


def build_group_confirm_prompt(
    *,
    entry: Dict[str, Any],
    shown: Sequence[int],
    uniform: bool = False,
    stack_context: str = "",
) -> Tuple[str, str]:
    """System + user prompt for one grouped-confirmation call: the pattern, then
    a numbered excerpt for each member in `shown` (not one representative and a
    list of file names)."""
    system = (
        f"{_GROUP_CONFIRM_SYSTEM}\n\n{_GROUP_RESPONSE_SCHEMA}\n\n"
        f"Tech stack: {stack_context or 'unknown'}\n"
        f"OWASP Top 10:2021 categories: {', '.join(OWASP_TOP_10_2021)}"
    )
    candidate = _candidate_json(entry)
    user = (
        f"Pattern ({candidate['occurrence_count']} occurrence(s) in this repository; "
        f"files: {candidate['occurrence_files']}):\n"
        f"{json.dumps(candidate, ensure_ascii=False)}\n\n"
        f"Occurrences to decide ({len(shown)} shown"
        + (f" of {candidate['occurrence_count']}" if len(shown) < candidate["occurrence_count"] and not uniform else "")
        + "):\n"
        + _render_members(entry, shown, uniform) + "\n"
    )
    return system, user


_GROUP_CONFIRM_BATCH_SYSTEM = (
    _GROUP_CONFIRM_SYSTEM + "\n\n"
    "You will be shown multiple independent patterns, each tagged with a "
    "group_index and each with its own occurrence ids (m1, m2, ...). Return one "
    "decision per occurrence shown, each carrying its pattern's group_index and "
    "its occurrence id — never merge, skip, or invent patterns or occurrences."
)

_GROUP_BATCH_RESPONSE_SCHEMA = """Output format — one JSON object with exactly one decision per occurrence shown:
{"decisions": [{
  "group_index": <int, matches the pattern's group_index>,
  "member": "<the occurrence id within that pattern, e.g. m1>",
  "verdict": "true_positive" | "false_positive",
  "confidence": <0.0-1.0, how sure you are of this verdict (1.0 = certain), whichever verdict it is>,
  "verdict_reason": "<why this occurrence is/isn't a real issue — required, one short sentence>",
  "ai_fix": "<at most 2 sentences; only on the FIRST true_positive occurrence of a pattern, omitted on every other>"
}, ...]}"""


def build_group_confirm_batch_prompt(
    *,
    plans: Sequence[Dict[str, Any]],
    stack_context: str = "",
) -> Tuple[str, str]:
    """System + user prompt for one batched call covering several groups. Each
    plan is {"entry", "shown", "uniform"}; candidate metadata for all groups is
    one compact JSON array and each group's numbered occurrence excerpts follow
    as a separately labeled block, so index alignment never depends on the
    order of the model's response."""
    candidates = []
    blocks = []
    for plan in plans:
        entry = plan["entry"]
        candidates.append({"group_index": entry["group_index"], **_candidate_json(entry)})
        blocks.append(
            f"Pattern {entry['group_index']} — occurrences to decide ({len(plan['shown'])} shown):\n"
            + _render_members(entry, plan["shown"], plan["uniform"])
        )
    system = (
        f"{_GROUP_CONFIRM_BATCH_SYSTEM}\n\n{_GROUP_BATCH_RESPONSE_SCHEMA}\n\n"
        f"Tech stack: {stack_context or 'unknown'}\n"
        f"OWASP Top 10:2021 categories: {', '.join(OWASP_TOP_10_2021)}"
    )
    user = (
        f"Patterns ({len(plans)}), one per line:\n"
        + "\n".join(json.dumps(c, ensure_ascii=False) for c in candidates) + "\n\n"
        + "\n\n".join(blocks) + "\n"
    )
    return system, user


def _decisions_by_member(
    items: Sequence[Any], shown: Sequence[int], group_index: Optional[int] = None
) -> Dict[int, Dict[str, Any]]:
    """Which shown member each decision is about. Ids are matched exactly; a
    decision without an id is accepted only when it is the one decision for the
    one member shown. Decisions about occurrences that were not shown are ignored."""
    ids = {_member_id(i): i for i in shown}
    scoped = [
        it for it in items or []
        if isinstance(it, dict) and (group_index is None or it.get("group_index") == group_index)
    ]
    out: Dict[int, Dict[str, Any]] = {}
    for item in scoped:
        member = str(item.get("member") or "").strip().lower()
        if member in ids and ids[member] not in out:
            out[ids[member]] = item
    if not out and len(shown) == 1 and len(scoped) == 1 and not scoped[0].get("member"):
        out[shown[0]] = scoped[0]
    return out


def _new_state(entry: Dict[str, Any]) -> Dict[str, Any]:
    return {"entry": entry, "results": {}, "shown": set(), "reasons": {}, "failure": None,
            "uniform": False, "detail": {}}


def _record_round(
    state: Dict[str, Any], shown: Sequence[int], decisions: Dict[int, Dict[str, Any]],
    *, uniform: bool, cache_hit: bool, usage: Optional[Dict[str, Any]],
) -> None:
    variant_of = _variant_of(state["entry"])
    if uniform:
        state["uniform"] = True
    for idx in shown:
        # A shown member stands for every member of identical code.
        variant = variant_of[idx]
        state["shown"].update(variant)
        item = decisions.get(idx)
        if item is None:
            # Keep a more specific earlier reason (an unrecognised verdict) over
            # the blanket "nothing came back" of a follow-up that found nothing.
            for member in variant:
                state["reasons"].setdefault(member, "llm_missing_verdict")
            continue
        result = _confirm_result_from_item(item, usage=usage)
        if result["error"] is not None:
            for member in variant:
                state["reasons"][member] = result["unresolved_reason"]
                state["detail"][member] = result["error"]
            continue
        result["result_cache_hit"] = cache_hit
        for member in variant:
            state["reasons"].pop(member, None)
            state["results"][member] = dict(result)


def _finalize_state(state: Dict[str, Any]) -> Dict[str, Any]:
    """Per-member results, aligned with `entry["members"]`; every member that no
    decision covers is unverified with the reason it is."""
    entry = state["entry"]
    total = len(entry["members"])
    results: List[Dict[str, Any]] = []
    for idx in range(total):
        if idx in state["results"]:
            results.append(state["results"][idx])
            continue
        if state["failure"]:
            reason = state["failure"]
        elif idx in state["reasons"]:
            reason = state["reasons"][idx]
        else:
            reason = "llm_missing_verdict" if idx in state["shown"] else "not_in_sample"
        results.append({
            "verdict": VERDICT_UNVERIFIED, "confidence": None, "verdict_reason": "", "ai_fix": None,
            "error": state["detail"].get(idx) or reason, "unresolved_reason": reason,
        })
    reviewed = len(state["results"])
    return {
        "results": results, "reviewed": reviewed, "total": total, "uniform": state["uniform"],
        "not_in_sample": sum(1 for r in results if r["unresolved_reason"] == "not_in_sample"),
        "error": None if reviewed else (results[0]["error"] if results else "empty group"),
    }


def _follow_up_indices(state: Dict[str, Any]) -> List[int]:
    """Members still without a decision, shown-but-unanswered first."""
    total = len(state["entry"]["members"])
    undecided = [i for i in range(total) if i not in state["results"]]
    return [i for i in undecided if i in state["shown"]] + [i for i in undecided if i not in state["shown"]]


def _ask_group(
    state: Dict[str, Any], indices: Sequence[int], *, stack_context: str,
    usage: Optional[Dict[str, Any]], llm_provider: Optional[str], llm_model: Optional[str],
    call_llm_fn: Callable[..., str], extra_user: str = "",
) -> None:
    """One call for one group over `indices`: plan, ask (one JSON retry), record.
    `extra_user` is appended to the prompt (a retry names the contradiction)."""
    entry = state["entry"]
    shown, _left, uniform = _plan_members(entry, indices)
    system, user = build_group_confirm_prompt(
        entry=entry, shown=shown, uniform=uniform, stack_context=stack_context,
    )
    if extra_user:
        user = user + "\n\n" + extra_user

    def _call(prompt: str) -> str:
        with _INFLIGHT:
            return call_llm_fn(
                system, prompt, max_tokens=max(512, GROUP_CONFIRM_TOKENS_PER_MEMBER * len(shown)), temperature=0.0,
                usage=usage, step=CONFIRM_STEP,
                provider=llm_provider, model=llm_model, json_mode=True,
            )

    try:
        raw_text = _call(user)
        items, err = parse_llm_json_array(raw_text)
        if err and not items:
            raw_text = _call(
                user + "\n\nYour previous response could not be parsed as JSON. "
                'Respond with the {"decisions": [...]} JSON object only '
                "— no prose, no markdown fences."
            )
            items, err = parse_llm_json_array(raw_text)
    except Exception as exc:  # one bad group must not kill the whole pass
        state["failure"] = unresolved_reason_for_exception(exc)
        state["detail"].update({i: f"{type(exc).__name__}: {exc}" for i in shown})
        state["shown"].update(shown)
        return
    _record_round(
        state, shown, _decisions_by_member(items, shown), uniform=uniform,
        cache_hit=last_call_was_cache_hit(), usage=usage,
    )


def confirm_finding_group(
    *,
    entry: Dict[str, Any],
    stack_context: str = "",
    usage: Optional[Dict[str, Any]] = None,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    call_llm_fn: Callable[..., str] = call_llm,
    state: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """TP/FP-confirm a group member by member.

    One call shows as many members as the character budget allows, each with
    its own excerpt, and asks for one decision per member id. Members the
    response left out, and members the budget could not show, get one follow-up
    call carrying just their excerpts. What is still undecided after that is
    `unverified`: `llm_missing_verdict` when it was shown, `not_in_sample` when
    it never fit. No member ever takes a sibling's verdict — except a member of
    identical code (same signature *and* same normalized excerpt, `_variant_of`):
    only one of those is shown, and its decision is, verifiably, a decision for
    each.

    Returns {"results" (one per member, in `entry["members"]` order),
    "reviewed", "total", "not_in_sample", "uniform", "error"}; `error` is set
    only when no member could be decided at all."""
    kwargs = dict(stack_context=stack_context, usage=usage, llm_provider=llm_provider,
                  llm_model=llm_model, call_llm_fn=call_llm_fn)
    state = state or _new_state(entry)
    if not state["shown"]:
        _ask_group(state, list(range(len(entry["members"]))), **kwargs)
    remaining = _follow_up_indices(state)
    if remaining and not state["failure"]:
        _ask_group(state, remaining, **kwargs)
    outcome = _finalize_state(state)
    if entry.get("explain", True):
        outcome = _resolve_member_contradictions(entry, state, outcome, **kwargs)
    return outcome


def _probe_for(entry: Dict[str, Any], index: int, result: Dict[str, Any]) -> Dict[str, Any]:
    """The member as `explanation_check` reads it once the model has answered."""
    member = entry["members"][index]
    return {
        "verdict": result["verdict"], "verdict_reason": result["verdict_reason"],
        "ai_fix": result["ai_fix"], "line": member.get("line"), "file_path": member.get("file_path"),
        "facts": member.get("facts"), "kind": "regex", "sink": "", "source": "",
    }


def _contradictions_of(entry: Dict[str, Any], index: int, result: Dict[str, Any]) -> List[Dict[str, str]]:
    probe = _probe_for(entry, index, result)
    member = entry["members"][index]
    text = entry["text_for"](member.get("file_path") or "")
    facts = member.get("facts") if isinstance(member.get("facts"), dict) else None
    return explanation_check.check_explanation(probe, facts, text)


def _resolve_member_contradictions(
    entry: Dict[str, Any], state: Dict[str, Any], outcome: Dict[str, Any], *,
    stack_context: str, usage: Optional[Dict[str, Any]], llm_provider: Optional[str],
    llm_model: Optional[str], call_llm_fn: Callable[..., str],
) -> Dict[str, Any]:
    """A member decision whose explanation contradicts its code gets one retry of
    just those members (the same prompt plus a `Deterministic facts:` block);
    one that still contradicts, or had no budget for a retry, is unverified /
    explanation_contradiction. A wording check never dismisses a member."""
    results = outcome["results"]
    found: Dict[int, List[Dict[str, str]]] = {}
    for index, result in enumerate(results):
        if result.get("error") is not None:
            continue
        contradictions = _contradictions_of(entry, index, result)
        if contradictions:
            found[index] = contradictions
            for c in contradictions:
                bump_counter(usage, "explanation_contradictions", c["check"])
    if not found:
        return outcome
    # A decision stands for every member of identical code: one retry per variant.
    variant_of = _variant_of(entry)
    retry_indices = sorted({variant_of[index][0] for index in found})
    retried: Dict[int, Dict[str, Any]] = {}
    if stage_has_budget(usage, CONFIRM_STEP):
        bump_counter(usage, "explanation_contradictions", "retries")
        block = explanation_check.contradictions_block(
            [{"contradictions": found[i]} for i in retry_indices],
            labels=[_member_id(i) for i in retry_indices],
        )
        retry_state = _new_state(entry)
        _ask_group(
            retry_state, retry_indices, stack_context=stack_context, usage=usage,
            llm_provider=llm_provider, llm_model=llm_model, call_llm_fn=call_llm_fn, extra_user=block,
        )
        retried = retry_state["results"]
    reviewed = outcome["reviewed"]
    for index, contradictions in found.items():
        again = retried.get(index)
        if again is not None and not _contradictions_of(entry, index, again):
            results[index] = again
            bump_counter(usage, "explanation_contradictions", "retry_resolved")
            continue
        listed = "; ".join(c["detail"] for c in (
            _contradictions_of(entry, index, again) if again is not None else contradictions
        ))
        results[index] = {
            "verdict": VERDICT_UNVERIFIED, "confidence": None, "ai_fix": None,
            "verdict_reason": (
                f"The explanation contradicts the code or its own verdict: {listed}. "
                f"(The model's verdict was {results[index]['verdict']}.)"
            ),
            "error": "explanation contradiction", "unresolved_reason": "explanation_contradiction",
            "detail": {"contradictions": contradictions, "model_verdict": results[index]["verdict"]},
        }
        reviewed -= 1
    return {**outcome, "results": results, "reviewed": reviewed,
            "error": None if reviewed else outcome["error"] or "explanation contradiction"}


def confirm_finding_group_batch(
    *,
    entries: Sequence[Dict[str, Any]],
    stack_context: str = "",
    usage: Optional[Dict[str, Any]] = None,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    call_llm_fn: Callable[..., str] = call_llm,
) -> Dict[int, Dict[str, Any]]:
    """Member-by-member confirmation of several groups in one LLM call, falling
    back to `confirm_finding_group` for what the batch did not resolve.

    A batch call that raises, or whose response is unparseable even after one
    retry, does not leave its groups unverified: each group gets its own
    confirm_finding_group call. A response that parses but decides only some
    members of a group sends the rest of that group to a follow-up call. Only a
    group whose fallback call also fails ends up unverified with `error` set —
    the batch is purely a cost optimization, never a coverage reduction.
    Returns {group_index: confirm_finding_group's outcome} for every entry."""
    kwargs = dict(stack_context=stack_context, usage=usage, llm_provider=llm_provider,
                  llm_model=llm_model, call_llm_fn=call_llm_fn)
    states: Dict[int, Dict[str, Any]] = {e["group_index"]: _new_state(e) for e in entries}
    plans = []
    for entry in entries:
        shown, _left, uniform = _plan_members(entry, list(range(len(entry["members"]))))
        plans.append({"entry": entry, "shown": shown, "uniform": uniform})
    system, user = build_group_confirm_batch_prompt(plans=plans, stack_context=stack_context)
    max_tokens = max(512, GROUP_CONFIRM_TOKENS_PER_MEMBER * sum(len(p["shown"]) for p in plans))

    def _call(prompt: str) -> str:
        with _INFLIGHT:
            return call_llm_fn(
                system, prompt, max_tokens=max_tokens, temperature=0.0,
                usage=usage, step=CONFIRM_STEP,
                provider=llm_provider, model=llm_model, json_mode=True,
            )

    answered: Set[int] = set()
    try:
        raw_text = _call(user)
        items, err = parse_llm_json_array(raw_text)
        if err and not items:
            raw_text = _call(
                user + "\n\nYour previous response could not be parsed as JSON. "
                'Respond with the {"decisions": [...]} JSON object only — no prose, '
                "no markdown fences."
            )
            items, err = parse_llm_json_array(raw_text)
        cache_hit = last_call_was_cache_hit()
        for plan in plans:
            gi = plan["entry"]["group_index"]
            decisions = _decisions_by_member(items, plan["shown"], gi)
            if decisions:
                answered.add(gi)
                _record_round(states[gi], plan["shown"], decisions, uniform=plan["uniform"],
                              cache_hit=cache_hit, usage=usage)
    except Exception:
        pass  # whole batch failed to call/parse — every group falls back below

    outcomes: Dict[int, Dict[str, Any]] = {}
    for entry in entries:
        gi = entry["group_index"]
        # A group the batch never answered starts over on its own; one it answered
        # in part only asks about what is still undecided.
        outcomes[gi] = confirm_finding_group(
            entry=entry, state=states[gi] if gi in answered else None, **kwargs,
        )
    return outcomes


def group_confirm_unverified_findings(
    *,
    file_results: List[Dict[str, Any]],
    repo_root: Path,
    rules: List[RegexRule],
    stack_context: str = "",
    usage: Optional[Dict[str, Any]] = None,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    call_llm_fn: Callable[..., str] = call_llm,
    group_workers: int = DEFAULT_FILE_WORKERS,
    severities: Set[str] = UNVERIFIED_FINDING_SEVERITIES,
    verdict_updates_writer: Optional[Callable[[str, List[Dict[str, Any]]], None]] = None,
    on_group: Optional[Callable[[Dict[str, Any]], None]] = None,
    group_cap: Optional[int] = None,
    groups_per_call: int = 1,
    occurrence_validators: bool = True,
) -> Dict[str, Any]:
    """Group unverified findings (via `group_unverified_findings`) and confirm
    every member of each group with an LLM, mutating each member finding dict
    in place (see `confirm_finding_group` for how members are decided and what
    stays unverified).

    `group_cap`, when set, confirms only the top-N groups by occurrence count
    (the biggest collapses first) and leaves the rest unverified — a backstop
    against repos with hundreds of groups. `groups_per_call` batches multiple
    groups into one LLM call (1 = one call per group) to amortize the shared
    system-prompt/OWASP-label overhead across a batch.

    `verdict_updates_writer(file_path, updates)`, when given, is called once
    per distinct file among all group members with the per-finding update
    dicts ({rule_id, line, verdict, confidence, verdict_reason, ai_fix,
    review_coverage, ...}) so a caller can persist the change onto
    already-written DB rows.
    """
    grouping = group_unverified_findings(file_results, severities=severities)
    groups = grouping["members_by_key"]
    # Biggest collapses first; ties by key, so the order (and with it every
    # prompt) does not depend on the order files happened to finish scanning.
    by_occurrence = sorted(grouping["group_order"], key=lambda k: (-len(groups[k]), repr(k)))
    confirm_keys = by_occurrence[:group_cap] if group_cap else by_occurrence
    skipped_keys = by_occurrence[group_cap:] if group_cap else []

    rules_by_id = {rule.id: rule for rule in rules}
    text_cache: Dict[str, str] = {}
    text_cache_lock = threading.Lock()

    def _text_for(path: str) -> str:
        with text_cache_lock:
            cached = text_cache.get(path)
        if cached is not None:
            return cached
        text = _read_text(repo_root, path) or ""
        with text_cache_lock:
            text_cache[path] = text
        return text

    def _entry(group_index: int, key: tuple) -> Dict[str, Any]:
        # Members with the strongest reachability evidence come first: they are
        # the most informative to show when the budget cannot show them all.
        # Ties are ordered by location, so a prompt (and its cache entry) does
        # not depend on the order files happened to finish scanning.
        ordered = sorted(
            groups[key],
            key=lambda m: (
                reachability.evidence_rank(m.get("reachability")),
                m.get("file_path") or "", int(m.get("line") or 0),
            ),
        )
        return {
            "group_index": group_index,
            "members": ordered,
            "rule": rules_by_id.get(ordered[0].get("rule_id") or ""),
            "text_for": _text_for,
            "explain": occurrence_validators,
        }

    def _apply_outcome(entry: Dict[str, Any], outcome: Dict[str, Any]) -> None:
        members = entry["members"]
        coverage = {"reviewed": outcome["reviewed"], "total": outcome["total"]}
        # The model writes a fix once per pattern; every confirmed occurrence of
        # it gets that fix (guidance, not a verdict).
        pattern_fix = next(
            (r["ai_fix"] for r in outcome["results"]
             if r.get("error") is None and r["verdict"] == "true_positive" and r.get("ai_fix")),
            None,
        )
        note = f"Reviewed {outcome['reviewed']} of {outcome['total']} occurrences"
        for member, result in zip(members, outcome["results"]):
            member["review_coverage"] = coverage
            if result.get("error") is not None:
                reason = result.get("unresolved_reason") or "llm_call_failed"
                member["unresolved_reason"] = reason
                if reason == "explanation_contradiction":
                    member["verdict_reason"] = result.get("verdict_reason")
                    member["verdict"] = VERDICT_UNVERIFIED
                    member["confidence"] = None
                    member["contradictions"] = (result.get("detail") or {}).get("contradictions")
                if reason == "not_in_sample":
                    member["verdict_reason"] = (
                        f"Not reviewed: only {outcome['reviewed']} of {outcome['total']} occurrences "
                        f"of this pattern fit in the confirmation sample, and a verdict for one "
                        f"occurrence is not given to another."
                    )
                continue
            member["unresolved_reason"] = None
            member["result_cache_hit"] = bool(result.get("result_cache_hit"))
            member["verdict"] = result["verdict"]
            member["confidence"] = result["confidence"]
            member["verdict_reason"] = f"{result['verdict_reason']} ({note})"
            if result["verdict"] == "true_positive" and (result.get("ai_fix") or pattern_fix):
                member["ai_fix"] = result.get("ai_fix") or pattern_fix
            # A deterministic proof or fact on this occurrence still outranks
            # the model's answer for it.
            reapply_precedence(member)
            reachability.apply_confidence(member)

    def _outcome_record(entry: Dict[str, Any], outcome: Dict[str, Any]) -> Dict[str, Any]:
        results = outcome["results"]
        decided = [r for r in results if r.get("error") is None]
        verdicts = {r["verdict"] for r in decided}
        return {
            "key": entry["key"], "members": entry["members"], **outcome,
            "verdict": "true_positive" if "true_positive" in verdicts
            else ("false_positive" if verdicts else VERDICT_UNVERIFIED),
        }

    def _run(item: Tuple[int, tuple]) -> Dict[str, Any]:
        entry = _entry(*item)
        entry["key"] = item[1]
        outcome = confirm_finding_group(
            entry=entry, stack_context=stack_context, usage=usage,
            llm_provider=llm_provider, llm_model=llm_model, call_llm_fn=call_llm_fn,
        )
        _apply_outcome(entry, outcome)
        return _outcome_record(entry, outcome)

    def _run_batch(batch: List[Tuple[int, tuple]]) -> List[Dict[str, Any]]:
        entries = []
        for i, (_n, key) in enumerate(batch):
            entry = _entry(i, key)
            entry["key"] = key
            entries.append(entry)
        outcomes_by_index = confirm_finding_group_batch(
            entries=entries, stack_context=stack_context, usage=usage,
            llm_provider=llm_provider, llm_model=llm_model, call_llm_fn=call_llm_fn,
        )
        records = []
        for entry in entries:
            outcome = outcomes_by_index[entry["group_index"]]
            _apply_outcome(entry, outcome)
            records.append(_outcome_record(entry, outcome))
        return records

    numbered = list(enumerate(confirm_keys))
    outcomes: List[Dict[str, Any]] = []
    if groups_per_call <= 1:
        if len(numbered) > 1 and group_workers > 1:
            with ThreadPoolExecutor(max_workers=min(group_workers, len(numbered))) as pool:
                outcomes = list(pool.map(_run, numbered))
        else:
            outcomes = [_run(item) for item in numbered]
    else:
        # Pack groups by what they cost to show (one occurrence per variant of
        # identical code, at most GROUP_CONFIRM_MAX_SHOWN), not by a fixed count,
        # so no call asks for an answer long enough to time out.
        batches: List[List[Tuple[int, tuple]]] = []
        current: List[Tuple[int, tuple]] = []
        load = 0
        for item in numbered:
            weight = min(GROUP_CONFIRM_MAX_SHOWN, variant_count(_entry(0, item[1])))
            if current and (len(current) >= groups_per_call or load + weight > GROUP_CONFIRM_BATCH_MAX_SHOWN):
                batches.append(current)
                current, load = [], 0
            current.append(item)
            load += weight
        if current:
            batches.append(current)
        if len(batches) > 1 and group_workers > 1:
            with ThreadPoolExecutor(max_workers=min(group_workers, len(batches))) as pool:
                outcomes = [o for batch_outcomes in pool.map(_run_batch, batches) for o in batch_outcomes]
        else:
            outcomes = [o for batch in batches for o in _run_batch(batch)]

    for key in skipped_keys:
        for m in groups[key]:
            m["unresolved_reason"] = "cap_reached"

    for outcome in outcomes:
        bump_counter(usage, "group_confirm_coverage", "members_reviewed", outcome["reviewed"])
        bump_counter(usage, "group_confirm_coverage", "members_total", outcome["total"])
        bump_counter(usage, "group_confirm_coverage", "members_not_in_sample", outcome["not_in_sample"])

    if verdict_updates_writer is not None:
        updates_by_file: Dict[str, List[Dict[str, Any]]] = {}
        for outcome in outcomes:
            coverage = {"reviewed": outcome["reviewed"], "total": outcome["total"]}
            for m, result in zip(outcome["members"], outcome["results"]):
                path = m.get("file_path") or ""
                if result.get("error") is not None:
                    # Verdict, confidence and reasoning stay as they were (apart
                    # from the note a member that never fit is given); only the
                    # reason it is still undecided is recorded.
                    update = {
                        "rule_id": m.get("rule_id"), "line": m.get("line"),
                        "unresolved_reason": m.get("unresolved_reason"),
                        "review_coverage": coverage,
                    }
                    if m.get("unresolved_reason") in ("not_in_sample", "explanation_contradiction"):
                        update["verdict_reason"] = m.get("verdict_reason")
                    if m.get("unresolved_reason") == "explanation_contradiction":
                        update.update(
                            verdict=VERDICT_UNVERIFIED, confidence=None,
                            decision_detail={"contradictions": m.get("contradictions")},
                        )
                else:
                    update = {
                        "rule_id": m.get("rule_id"), "line": m.get("line"),
                        "verdict": m.get("verdict"), "confidence": m.get("confidence"),
                        "verdict_reason": m.get("verdict_reason"), "ai_fix": m.get("ai_fix"),
                        "unresolved_reason": m.get("unresolved_reason"),
                        "reason_tag": m.get("reason_tag"),
                        "review_coverage": coverage,
                        "result_cache_hit": bool(m.get("result_cache_hit")),
                    }
                updates_by_file.setdefault(path, []).append(update)
        for key in skipped_keys:
            for m in groups[key]:
                updates_by_file.setdefault(m.get("file_path") or "", []).append({
                    "rule_id": m.get("rule_id"), "line": m.get("line"),
                    "unresolved_reason": "cap_reached",
                })
        for path, updates in updates_by_file.items():
            verdict_updates_writer(path, updates)

    if on_group is not None:
        for outcome in outcomes:
            on_group(outcome)

    tp = sum(1 for o in outcomes if o["verdict"] == "true_positive")
    fp = sum(1 for o in outcomes if o["verdict"] == "false_positive")
    errors = sum(1 for o in outcomes if o["error"] is not None)
    return {
        "candidate_count": grouping["candidate_count"],
        "group_count": len(by_occurrence),
        "confirm_group_count": len(confirm_keys),
        "skipped_group_count": len(skipped_keys),
        "tp_group_count": tp,
        "fp_group_count": fp,
        "error_group_count": errors,
        "confirmed_finding_count": sum(o["reviewed"] for o in outcomes),
        "members_reviewed": sum(o["reviewed"] for o in outcomes),
        "members_total": sum(o["total"] for o in outcomes),
        "members_not_in_sample": sum(o["not_in_sample"] for o in outcomes),
    }
