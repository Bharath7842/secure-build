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

from llm_client import call_llm, parse_llm_json_array

from .owasp_map import OWASP_TOP_10_2021, owasp_for_rule
from .regex_scan import RegexRule, rules_for_prompt, scan_one_file, _SQL_CONCAT_CATALOG_IDS

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
SKELETON_MAX_LINES = 110
SKELETON_LINE_MAX_CHARS = 200

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

# Findings below this confidence are dropped when they are also unevidenced
# generic-catalog echoes. Evidenced findings survive at any confidence.
UNEVIDENCED_CONFIDENCE_FLOOR = 0.6

# A false_positive-verdict deep-scan finding at or below this confidence (=
# "how sure you are this is exploitable") is a confident self-dismissal by the
# model — suppressed outright when suppress_low_confidence_false_positives is
# on, regardless of rule_id (unlike UNEVIDENCED_CONFIDENCE_FLOOR, which only
# applies to the noisy-rule allowlist).
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
    "cvs", "xsd", "configuration", "config",
    "node_modules", ".settings", ".idea",
})
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


def lang_for_path(path: str) -> Optional[str]:
    """Extension -> rule-catalog language tag (for catalog filtering and
    chunk-boundary heuristics). None for unrecognized extensions — such files
    still get scanned, just with the universal (untagged) rule subset."""
    return _EXT_TO_LANG.get(Path(path).suffix.lower())


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


def build_file_skeleton(text: str, lang: Optional[str], *, max_lines: int = SKELETON_MAX_LINES) -> str:
    """A compact whole-file map: imports, declarations, and every line that
    looks like an untrusted-input source or a dangerous sink.

    This is the main recall fix for chunked files. Without it, a chunk holding
    `stmt.executeQuery(sql)` has no way to know `sql` was built from
    `request.getParameter("id")` 300 lines earlier, and the model correctly but
    uselessly reports "cannot determine if input is trusted"."""
    lines = text.splitlines()
    picked: List[str] = []
    truncated = False
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        keep = False
        if i <= 60 and _IMPORT_RE.match(line):
            keep = True
        elif _TAINT_SOURCE_RE.search(line) or _TAINT_SINK_RE.search(line):
            keep = True
        else:
            decl_re = _BOUNDARY_PATTERNS.get(lang or "")
            if decl_re is not None and decl_re.match(line) and (
                "(" in stripped or " class " in f" {stripped} " or "interface" in stripped
            ):
                keep = True
        if keep:
            picked.append(f"{i}: {stripped[:SKELETON_LINE_MAX_CHARS]}")
            if len(picked) >= max_lines:
                truncated = True
                break
    if truncated:
        picked.append("… (skeleton truncated)")
    return "\n".join(picked)


def _read_text(repo_root: Path, rel_path: str) -> Optional[str]:
    try:
        return (repo_root / rel_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def is_non_source_path(rel_path: str) -> bool:
    return Path(rel_path).suffix.lower() in NON_SOURCE_FILE_EXTS


def is_excluded_from_finding_scan(rel_path: str) -> bool:
    """True for schema, IDE, CVS, config/configuration/, log4j config, and
    shell-script paths.

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
    return None


# --- prompt -----------------------------------------------------------------

_SYSTEM_HEAD = (
    "You are a senior application security engineer performing manual source-code "
    "review. You are shown one code chunk from a CRITICAL-risk file, a skeleton map "
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
    "- Do NOT flag JDBC ResultSet getters (rs.getString, getInt, etc.) as SQL "
    "injection; reading a column from a query result is not building SQL.\n"
    "- Do NOT flag string concatenation that does not build a query, command, path, "
    "or markup.\n"
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
    "garbled decompiler output, etc.), return [] — do not emit a finding about "
    "being unable to analyze.\n\n"
    "Respond with a JSON array only. No prose, no markdown fences."
)


def build_system_prompt(
    catalog: List[Dict[str, Any]],
    stack_context: str,
    owasp_labels: Sequence[str] = OWASP_TOP_10_2021,
) -> str:
    """Stable-per-(language, stack) prefix. Kept separate from the user block so
    providers with prompt caching can reuse it across every chunk and file."""
    return (
        f"{_SYSTEM_HEAD}\n\n"
        f"Tech stack: {stack_context or 'unknown'}\n"
        f"OWASP Top 10:2021 categories: {', '.join(owasp_labels)}\n\n"
        "Known vulnerability pattern catalog (guidance only — not exhaustive, not a gate):\n"
        f"{json.dumps(catalog, indent=2)}"
    )


_RESPONSE_SCHEMA = """Return a JSON array. Each item:
{
  "verdict": "true_positive" | "false_positive",
  "owasp_category": "<one of the OWASP Top 10:2021 labels>",
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "confidence": <0.0-1.0, how sure you are this is exploitable>,
  "cwe": "CWE-XXX or empty string",
  "rule_id": "<catalog id if this matches one, else \\"llm-extra\\">",
  "title": "short title",
  "line": <line number from the numbered code above>,
  "source": "<the untrusted input expression, or \\"\\" if none identified>",
  "sink": "<the dangerous call this reaches>",
  "data_flow": "<one line: how source reaches sink, naming intermediate variables>",
  "snippet": "<short excerpt; include the vulnerable line plus a few neighbors>",
  "verdict_reason": "why this is/isn't a real issue — required, even for false_positive",
  "ai_fix": "<remediation guidance, only when verdict is true_positive>"
}
If there are no issues in this chunk, return []."""


def build_user_prompt(
    *,
    file_path: str,
    chunk_text: str,
    start_line: int,
    skeleton: str = "",
) -> str:
    lines = chunk_text.splitlines()
    numbered = "\n".join(f"{start_line + i}: {line}" for i, line in enumerate(lines))
    skeleton_block = (
        "File skeleton (imports, declarations, and every input source / dangerous "
        "sink line in the WHOLE file — use it to trace flows that start outside "
        "this chunk; do not report findings on lines not shown in the code below):\n"
        f"```\n{skeleton}\n```\n\n"
        if skeleton else ""
    )
    return (
        f"File: {file_path}\n\n"
        f"{skeleton_block}"
        f"Code under review (lines {start_line}-{start_line + max(len(lines) - 1, 0)}):\n"
        f"```\n{numbered}\n```\n\n"
        f"{_RESPONSE_SCHEMA}\n"
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
    fields = ("id", "title", "description", "cwe", "severity", "owasp") + (
        ("pattern",) if keep_pattern else ()
    )
    return [{k: rule[k] for k in fields if k in rule} for rule in catalog]


# --- normalization / anchoring / dedupe -------------------------------------

# "unverified" is never produced by an LLM — it is what regex-only triage
# records, and it must round-trip through _normalize_verdict untouched. Without
# it here the fallthrough at the end of _normalize_verdict would silently
# rewrite every regex-only finding to false_positive.
VERDICT_UNVERIFIED = "unverified"
_VALID_VERDICTS = {"true_positive", "false_positive", VERDICT_UNVERIFIED}
_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_NEGATION_RE = re.compile(r"\b(not|no|isn'?t|non)\b")


def _normalize_verdict(raw: Any) -> str:
    """Tolerate other vocabularies (e.g. "TRUE_POSITIVE", "confirmed") seen
    elsewhere in this codebase's LLM prompts, without the old bug where
    "not a true positive" resolved to true_positive."""
    text = str(raw or "").strip().lower().replace("-", "_")
    if text in _VALID_VERDICTS:
        return text
    if "false" in text or text.startswith("fp"):
        return "false_positive"
    if _NEGATION_RE.search(text):
        return "false_positive"
    if "true" in text or "confirm" in text or text.startswith("tp"):
        return "true_positive"
    return "false_positive"


def _normalize_confidence(raw: Any, verdict: str) -> float:
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
) -> Optional[Dict[str, Any]]:
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

    verdict = _normalize_verdict(raw.get("verdict"))
    severity = str(raw.get("severity") or "MEDIUM").strip().upper()
    if severity not in _VALID_SEVERITIES:
        severity = "MEDIUM"
    cwe = str(raw.get("cwe") or "").strip() or None
    owasp_category = str(raw.get("owasp_category") or "").strip()
    if owasp_category not in OWASP_TOP_10_2021:
        owasp_category = owasp_for_rule(cwe, None)
    reason = str(raw.get("verdict_reason") or "").strip() or "No reason provided by the model."
    ai_fix = raw.get("ai_fix")
    ai_fix = str(ai_fix).strip() if verdict == "true_positive" and ai_fix else None

    kind = str(raw.get("kind") or kind).strip() or "llm"
    return {
        "verdict": verdict,
        "confidence": _normalize_confidence(raw.get("confidence"), verdict),
        "owasp_category": owasp_category,
        "severity": severity,
        "cwe": cwe,
        "rule_id": str(raw.get("rule_id") or "llm-extra").strip() or "llm-extra",
        "title": str(raw.get("title") or "Untitled finding").strip()[:500],
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


def _dedupe_key(finding: Dict[str, Any]) -> tuple:
    """Group by line plus a coarse topic so the same issue reported under two
    different rule_ids across an overlap region collapses into one row."""
    title = re.sub(r"[^a-z]+", " ", str(finding.get("title") or "").lower()).strip()
    topic = " ".join(title.split()[:3])
    return (finding["line"], finding.get("cwe") or topic)


def merge_dedupe(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Dedupe on (line, cwe-or-topic), preferring true_positive over
    false_positive, then higher severity, then higher confidence."""
    best: Dict[tuple, Dict[str, Any]] = {}
    for f in findings:
        key = _dedupe_key(f)
        current = best.get(key)
        if current is None:
            best[key] = f
            continue
        cur_tp = current["verdict"] == "true_positive"
        new_tp = f["verdict"] == "true_positive"
        if new_tp != cur_tp:
            if new_tp:
                best[key] = f
            continue
        cur_rank = _SEVERITY_RANK.get(current["severity"], 9)
        new_rank = _SEVERITY_RANK.get(f["severity"], 9)
        if new_rank < cur_rank or (
            new_rank == cur_rank and f.get("confidence", 0) > current.get("confidence", 0)
        ):
            best[key] = f
    return sorted(best.values(), key=lambda f: (f["line"], f["rule_id"]))


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


def should_publish_finding(
    finding: Dict[str, Any],
    context_text: str = "",
    *,
    suppress_no_cwe: bool = True,
    suppress_http_findings: bool = False,
    suppress_low_confidence_false_positives: bool = False,
) -> bool:
    """Evidence-based suppression.

    The previous revision dropped every finding whose rule_id was a generic SQL
    concat catalog id, which deleted real SQL injections that happened to be
    tagged with one. Here a noisy id only suppresses when there is *also* no
    evidence: no query construction anywhere in the context window, no named
    untrusted source, and low confidence.

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
    dismissed it, regardless of rule_id."""
    if suppress_no_cwe and not (finding.get("cwe") or "").strip():
        return False
    if suppress_http_findings and _is_http_related_finding(finding):
        return False
    if (
        suppress_low_confidence_false_positives
        and finding.get("verdict") == "false_positive"
        and float(finding.get("confidence") or 0.0) <= FALSE_POSITIVE_SUPPRESS_CONFIDENCE_CEILING
    ):
        return False
    if _is_unanalyzable_meta_finding(finding):
        return False

    snippet = (finding.get("snippet") or "").strip()
    anchored = _anchored_line_from_context(context_text) if context_text else ""
    if _LOGGING_CALL_RE.search(snippet) or (anchored and _LOGGING_CALL_RE.search(anchored)):
        return False

    combined = " ".join([
        finding.get("title") or "",
        finding.get("data_flow") or "",
        finding.get("sink") or "",
        snippet,
        context_text,
    ]).lower()

    builds_sql = bool(_SQL_BUILD_RE.search(combined))

    # A bare ResultSet read with no query construction anywhere nearby is the
    # single most common false positive in Java scans. Still safe to drop.
    if _RESULTSET_READ_RE.search(snippet) and not builds_sql:
        return False

    if _is_noisy_rule(finding.get("rule_id", "")):
        if finding.get("verdict") != "true_positive":
            return False  # generic catalog echo marked FP — no tuning value
        has_source = bool((finding.get("source") or "").strip())
        confident = float(finding.get("confidence") or 0.0) >= UNEVIDENCED_CONFIDENCE_FLOOR
        return builds_sql or has_source or confident

    return True


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
) -> List[Dict[str, Any]]:
    """Enrich snippets with real source context, *then* apply suppression
    against that context. Order matters: judging a sink-only snippet before
    enrichment is what caused genuine injections to be filtered out."""
    out: List[Dict[str, Any]] = []
    for finding in findings:
        context = build_code_context(
            source_text, finding["line"], finding.get("snippet") or "",
        )
        if not should_publish_finding(
            finding, context,
            suppress_no_cwe=suppress_no_cwe, suppress_http_findings=suppress_http_findings,
            suppress_low_confidence_false_positives=suppress_low_confidence_false_positives,
        ):
            continue
        enriched = dict(finding)
        enriched["snippet"] = context
        out.append(enriched)
    return out


# --- LLM plumbing -----------------------------------------------------------

def files_for_risk_levels(
    module_plan: Dict[str, Any],
    levels: Set[str],
) -> List[Dict[str, Any]]:
    """Files at the given path-heuristic risk levels, excluding non-source and
    schema/CVS/log4j paths that stay in Discovery but are not finding-scanned."""
    wanted = {str(level).upper() for level in levels}
    return [
        entry for entry in module_plan.get("files", [])
        if str(entry.get("risk_level") or "").upper() in wanted
        and not is_non_source_path(entry.get("path") or "")
        and not is_excluded_from_finding_scan(entry.get("path") or "")
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
) -> Dict[str, Any]:
    """Scan one chunk. Returns {"findings": [...], "error": str|None}.

    A malformed JSON response gets one retry with an explicit repair nudge; if
    it still fails the error is returned rather than silently yielding zero
    findings, which is how the old version lost whole chunks.

    `usage` must be the shared scan usage dict so the $2 Bedrock cutoff in
    `llm_client._resolve_provider_for_call` can see running cost_usd.
    """
    system = system_prompt or build_system_prompt(catalog, stack_context)
    user = build_user_prompt(
        file_path=file_path, chunk_text=chunk["text"],
        start_line=chunk["start_line"], skeleton=skeleton,
    )

    def _call(prompt: str) -> str:
        with _INFLIGHT:
            return call_llm_fn(
                system, prompt,
                max_tokens=4096, temperature=0.0,
                usage=usage, step=llm_step,
                provider=llm_provider, model=llm_model,
            )

    try:
        raw_text = _call(user)
        items, err = parse_llm_json_array(raw_text)
        if err and not items:
            retry_user = (
                user
                + "\n\nYour previous response could not be parsed as JSON. "
                "Respond with a valid JSON array only — no prose, no markdown fences."
            )
            raw_text = _call(retry_user)
            items, err = parse_llm_json_array(raw_text)
    except Exception as exc:  # one bad chunk must not kill the tier
        return {"findings": [], "error": f"{type(exc).__name__}: {exc}"}

    findings: List[Dict[str, Any]] = []
    for item in items:
        norm = normalize_finding(
            item, file_path=file_path,
            chunk_start=chunk["start_line"], chunk_end=chunk["end_line"],
            source_lines=source_lines, kind=kind,
        )
        if norm is not None:
            findings.append(norm)
    return {"findings": findings, "error": err if (err and not items) else None}


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
    skeleton = build_file_skeleton(text, lang) if len(chunks) > 1 else ""

    def _run(indexed: Tuple[int, Dict[str, Any]]) -> Tuple[int, Dict[str, Any]]:
        idx, chunk = indexed
        if on_chunk_start is not None:
            with _CALLBACK_LOCK:
                on_chunk_start(idx, len(chunks), rel_path)
        return idx, scan_chunk(
            file_path=rel_path, chunk=chunk, catalog=catalog,
            stack_context=stack_context, skeleton=skeleton,
            source_lines=source_lines, usage=usage,
            llm_provider=llm_provider, llm_model=llm_model,
            call_llm_fn=call_llm_fn, system_prompt=system_prompt,
            llm_step=llm_step, kind="llm",
        )

    indexed_chunks = list(enumerate(chunks, start=1))
    if len(indexed_chunks) > 1 and chunk_workers > 1:
        with ThreadPoolExecutor(max_workers=min(chunk_workers, len(indexed_chunks))) as pool:
            outcomes = list(pool.map(_run, indexed_chunks))
    else:
        outcomes = [_run(item) for item in indexed_chunks]

    all_findings: List[Dict[str, Any]] = []
    chunk_errors: List[str] = []
    for _idx, outcome in sorted(outcomes, key=lambda pair: pair[0]):
        all_findings.extend(outcome["findings"])
        if outcome.get("error"):
            chunk_errors.append(outcome["error"])

    merged = finalize_findings(
        merge_dedupe(all_findings), text,
        suppress_no_cwe=suppress_no_cwe, suppress_http_findings=suppress_http_findings,
        suppress_low_confidence_false_positives=suppress_low_confidence_false_positives,
    )
    tp_count = sum(1 for f in merged if f["verdict"] == "true_positive")
    return {
        "file_path": rel_path,
        "chunks": len(chunks),
        "findings": merged,
        "tp_count": tp_count,
        "fp_count": len(merged) - tp_count,
        "read_error": False,
        "chunk_errors": chunk_errors,
    }


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
        )
        results[position] = result
        with _CALLBACK_LOCK:
            if findings_writer is not None:
                findings_writer(path, result["findings"])
            if on_file is not None:
                on_file(result)

    indexed_files = list(enumerate(critical_files))
    if total > 1 and file_workers > 1:
        with ThreadPoolExecutor(max_workers=min(file_workers, total)) as pool:
            list(pool.map(_run, indexed_files))
    else:
        for item in indexed_files:
            _run(item)

    final = [r for r in results if r is not None]
    return {
        "files_scanned": len(final),
        "tp_count": sum(r["tp_count"] for r in final),
        "fp_count": sum(r["fp_count"] for r in final),
        "chunk_errors": sum(len(r.get("chunk_errors") or []) for r in final),
        "files": final,
    }


# --- MEDIUM/LOW tier: regex first, then LLM triage of the hits only ---------

_TRIAGE_SYSTEM = (
    "You triage regex-scanner hits. You do not hunt for new issues.\n"
    "For each candidate decide true_positive or false_positive.\n"
    "A hit is a false_positive when the match is a test fixture, placeholder, "
    "comment, sample data, or otherwise not a real vulnerability.\n"
    "Respond with a JSON array only. No prose, no markdown fences."
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


def build_triage_prompts(
    *,
    file_path: str,
    source_text: str,
    hits: List[Dict[str, Any]],
    rules_by_id: Dict[str, RegexRule],
    stack_context: str = "",
) -> Tuple[str, str]:
    """System + user prompts for regex-hit triage (no extra findings).

    Carries only the hit candidates and a context window around each one — the
    full file body is deliberately never included.
    """
    candidates: List[Dict[str, Any]] = []
    context_blocks: List[str] = []
    for hit in hits:
        rule = rules_by_id.get(hit.get("rule") or "")
        line = int(hit.get("line") or 1)
        candidates.append({
            "rule_id": hit.get("rule"),
            "title": rule.title if rule else (hit.get("rule") or "unknown"),
            "description": rule.description if rule else "",
            "cwe": (rule.cwe if rule else "") or "",
            "severity": (rule.severity if rule else hit.get("severity")) or "LOW",
            "owasp": (rule.owasp if rule else "") or "",
            "line": line,
            "matched_text": hit.get("matched_text") or "",
        })
        context_blocks.append(
            f"--- hit {hit.get('rule')} at line {line} ---\n"
            + build_code_context(source_text, line, hit.get("matched_text") or "")
        )
    system = (
        f"{_TRIAGE_SYSTEM}\n\n"
        f"Tech stack: {stack_context or 'unknown'}\n"
        f"OWASP Top 10:2021 categories: {', '.join(OWASP_TOP_10_2021)}"
    )
    user = (
        f"File: {file_path}\n\n"
        "Candidates (triage these only; do not add other findings):\n"
        f"{json.dumps(candidates, indent=2)}\n\n"
        "Source context around each hit:\n"
        f"{chr(10).join(context_blocks)}\n\n"
        f"{_RESPONSE_SCHEMA}\n"
        "Return one object per candidate you reviewed. rule_id and line must "
        "match a candidate. Do not invent findings that are not in the list."
    )
    return system, user


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
) -> Dict[str, Any]:
    """One LLM call to TP/FP-triage the regex hits in a MEDIUM/LOW-risk file."""
    if not hits:
        return {
            "file_path": file_path, "chunks": 0, "findings": [],
            "tp_count": 0, "fp_count": 0, "read_error": False, "chunk_errors": [],
        }

    rules_by_id = {rule.id: rule for rule in rules}
    source_lines = source_text.splitlines()
    system, user = build_triage_prompts(
        file_path=file_path, source_text=source_text, hits=hits,
        rules_by_id=rules_by_id, stack_context=stack_context,
    )
    line_lo = min(int(h.get("line") or 1) for h in hits)
    line_hi = max(int(h.get("line") or 1) for h in hits)
    line_lo = max(1, line_lo - CONTEXT_LINES_BEFORE)
    line_hi = min(len(source_lines) or line_hi, line_hi + CONTEXT_LINES_AFTER)

    def _call(prompt: str) -> str:
        with _INFLIGHT:
            return call_llm_fn(
                system, prompt,
                max_tokens=4096, temperature=0.0,
                usage=usage, step="scan_triage_files",
                provider=llm_provider, model=llm_model,
            )

    try:
        raw_text = _call(user)
        items, err = parse_llm_json_array(raw_text)
        if err and not items:
            retry_user = (
                user
                + "\n\nYour previous response could not be parsed as JSON. "
                "Respond with a valid JSON array only — no prose, no markdown fences."
            )
            raw_text = _call(retry_user)
            items, err = parse_llm_json_array(raw_text)
    except Exception as exc:
        return {
            "file_path": file_path, "chunks": 1, "findings": [],
            "tp_count": 0, "fp_count": 0, "read_error": False,
            "chunk_errors": [f"{type(exc).__name__}: {exc}"],
        }

    findings: List[Dict[str, Any]] = []
    for item in items:
        if isinstance(item, dict) and not item.get("rule_id"):
            item = dict(item)
            item["rule_id"] = item.get("rule") or ""
        norm = normalize_finding(
            item if isinstance(item, dict) else {},
            file_path=file_path,
            chunk_start=line_lo, chunk_end=max(line_hi, line_lo),
            source_lines=source_lines, kind="regex",
        )
        if norm is None:
            continue
        if not _hit_matches_finding(norm, hits):
            continue
        findings.append(norm)

    merged = finalize_findings(merge_dedupe(findings), source_text)
    for finding in merged:
        finding["kind"] = "regex"
    tp_count = sum(1 for f in merged if f["verdict"] == "true_positive")
    return {
        "file_path": file_path,
        "chunks": 1,
        "findings": merged,
        "tp_count": tp_count,
        "fp_count": len(merged) - tp_count,
        "read_error": False,
        "chunk_errors": [err] if (err and not items) else [],
    }


def findings_from_hits(
    *,
    file_path: str,
    source_text: str,
    hits: List[Dict[str, Any]],
    rules_by_id: Dict[str, RegexRule],
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
            "verdict": VERDICT_UNVERIFIED,
            "verdict_reason": UNVERIFIED_REASON,
            "kind": "regex",
            "confidence": None,
        })
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
    """
    triage_files = entries if entries is not None else files_for_risk_levels(module_plan, TRIAGE_RISK_LEVELS)
    total = len(triage_files)
    results: List[Optional[Dict[str, Any]]] = [None] * total
    rules_by_id = {rule.id: rule for rule in rules}

    def _run(indexed: Tuple[int, Dict[str, Any]]) -> None:
        position, entry = indexed
        path = entry["path"]
        if on_file_start is not None:
            with _CALLBACK_LOCK:
                on_file_start(position + 1, total, path)
        lang = entry.get("lang") or lang_for_path(path)
        scanned = scan_one_file(
            repo_root, path, entry.get("module", "(root)"), rules,
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
            )
            # Deliberately NOT run through should_publish_finding: that gate
            # drops non-true_positive findings on noisy catalog rules, which
            # would delete every unverified finding here. It exists to suppress
            # findings an LLM invented; a regex hit is ground truth about what
            # matched, so the human reviewer gets to decide instead.
            result = {
                "file_path": path, "chunks": 0, "findings": findings,
                "tp_count": 0, "fp_count": 0,
                "unverified_count": len(findings),
                "read_error": False, "chunk_errors": [],
            }
        else:
            result = triage_regex_hits(
                file_path=path, source_text=text, hits=scanned["hits"],
                rules=rules, stack_context=stack_context, usage=usage,
                llm_provider=llm_provider, llm_model=llm_model,
                call_llm_fn=call_llm_fn,
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

_GROUP_CONFIRM_SYSTEM = (
    "You confirm whether a regex-matched code pattern is a real vulnerability. "
    "You are shown one representative occurrence of a pattern that was matched "
    "identically at one or more locations in this repository; the verdict you "
    "give will be applied to every occurrence of this exact pattern, so judge "
    "whether the construct itself — not just this one location — is generally "
    "a real issue.\n"
    "A hit is a false_positive when the match is a test fixture, placeholder, "
    "comment, sample data, or otherwise not a real vulnerability.\n"
    "Respond with a JSON array containing exactly one object. No prose, no "
    "markdown fences."
)

_GROUP_RESPONSE_SCHEMA = """Return a JSON array with exactly one object:
[{
  "verdict": "true_positive" | "false_positive",
  "confidence": <0.0-1.0>,
  "verdict_reason": "why this construct is/isn't a real issue — required",
  "ai_fix": "<remediation guidance, only when verdict is true_positive>"
}]"""


def group_key_for_finding(finding: Dict[str, Any]) -> tuple:
    """Same-issue key for unverified regex findings — mirrors
    app.services.scan_export._finding_group_key's regex branch."""
    rule_id = str(finding.get("rule_id") or "").strip()
    if rule_id and rule_id.lower() != "llm-extra":
        if finding.get("group_by_rule"):
            return ("rule", rule_id)
        matched = " ".join(str(finding.get("matched_text") or "").split())[:200]
        return ("rule", rule_id, matched)
    topic = re.sub(r"[^a-z0-9]+", " ", str(finding.get("title") or "").lower()).strip()
    topic = " ".join(topic.split()[:3])
    return ("topic", str(finding.get("cwe") or "").strip().upper(), topic, matched)


def build_group_confirm_prompt(
    *,
    representative: Dict[str, Any],
    occurrence_paths: Sequence[str],
    source_text: str,
    rule: Optional[RegexRule],
    stack_context: str = "",
) -> Tuple[str, str]:
    """System + user prompt for one grouped-confirmation call. Carries only the
    representative occurrence's context window plus a list of the other
    affected files — the full body of every occurrence is never sent."""
    line = int(representative.get("line") or 1)
    context = build_code_context(source_text, line, representative.get("matched_text") or "")
    shown = list(occurrence_paths[:10])
    extra = len(occurrence_paths) - len(shown)
    occurrence_note = ", ".join(shown) + (f", +{extra} more" if extra > 0 else "")
    candidate = {
        "rule_id": representative.get("rule_id"),
        "title": (rule.title if rule else representative.get("title")) or "",
        "description": (rule.description if rule else "") or "",
        "cwe": (rule.cwe if rule else representative.get("cwe")) or "",
        "severity": (rule.severity if rule else representative.get("severity")) or "LOW",
        "owasp": (rule.owasp if rule else representative.get("owasp_category")) or "",
        "matched_text": representative.get("matched_text") or "",
        "occurrence_count": len(occurrence_paths),
        "occurrence_files": occurrence_note,
    }
    system = (
        f"{_GROUP_CONFIRM_SYSTEM}\n\n"
        f"Tech stack: {stack_context or 'unknown'}\n"
        f"OWASP Top 10:2021 categories: {', '.join(OWASP_TOP_10_2021)}"
    )
    user = (
        f"Pattern (matched identically in {len(occurrence_paths)} location(s); "
        f"files: {occurrence_note}):\n"
        f"{json.dumps(candidate, indent=2)}\n\n"
        f"Representative occurrence — {representative.get('file_path')}:\n"
        f"```\n{context}\n```\n\n"
        f"{_GROUP_RESPONSE_SCHEMA}\n"
    )
    return system, user


def _confirm_result_from_item(item: Dict[str, Any]) -> Dict[str, Any]:
    verdict = _normalize_verdict(item.get("verdict"))
    confidence = _normalize_confidence(item.get("confidence"), verdict)
    reason = str(item.get("verdict_reason") or "").strip() or "No reason provided by the model."
    ai_fix = item.get("ai_fix")
    ai_fix = str(ai_fix).strip() if verdict == "true_positive" and ai_fix else None
    return {
        "verdict": verdict, "confidence": confidence,
        "verdict_reason": reason, "ai_fix": ai_fix, "error": None,
    }


def confirm_finding_group(
    *,
    representative: Dict[str, Any],
    occurrence_paths: Sequence[str],
    source_text: str,
    rule: Optional[RegexRule],
    stack_context: str = "",
    usage: Optional[Dict[str, Any]] = None,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    call_llm_fn: Callable[..., str] = call_llm,
) -> Dict[str, Any]:
    """One LLM call to TP/FP-confirm a group of identical unverified findings.

    Returns {"verdict", "confidence", "verdict_reason", "ai_fix", "error"}. On
    any failure (LLM error, unparseable response), returns verdict=unverified
    unchanged with `error` set, so callers can leave that group's findings
    untouched rather than mislabel them.
    """
    system, user = build_group_confirm_prompt(
        representative=representative, occurrence_paths=occurrence_paths,
        source_text=source_text, rule=rule, stack_context=stack_context,
    )

    def _call(prompt: str) -> str:
        with _INFLIGHT:
            return call_llm_fn(
                system, prompt,
                max_tokens=512, temperature=0.0,
                usage=usage, step="group_confirm_triage_findings",
                provider=llm_provider, model=llm_model,
            )

    try:
        raw_text = _call(user)
        items, err = parse_llm_json_array(raw_text)
        if err and not items:
            retry_user = (
                user
                + "\n\nYour previous response could not be parsed as JSON. "
                "Respond with a valid JSON array containing exactly one object "
                "— no prose, no markdown fences."
            )
            raw_text = _call(retry_user)
            items, err = parse_llm_json_array(raw_text)
    except Exception as exc:  # one bad group must not kill the whole pass
        return {
            "verdict": VERDICT_UNVERIFIED, "confidence": None,
            "verdict_reason": "", "ai_fix": None,
            "error": f"{type(exc).__name__}: {exc}",
        }

    item = items[0] if items and isinstance(items[0], dict) else None
    if item is None:
        return {
            "verdict": VERDICT_UNVERIFIED, "confidence": None,
            "verdict_reason": "", "ai_fix": None,
            "error": err or "empty or unparseable response",
        }

    return _confirm_result_from_item(item)


_GROUP_CONFIRM_BATCH_SYSTEM = (
    _GROUP_CONFIRM_SYSTEM + "\n\n"
    "You will be shown multiple independent patterns, each tagged with a "
    "group_index. Return exactly one verdict object per pattern shown, each "
    "carrying that same group_index — never merge, skip, or invent patterns."
)

_GROUP_BATCH_RESPONSE_SCHEMA = """Return a JSON array with exactly one object per pattern shown:
[{
  "group_index": <int, matches the pattern's group_index above>,
  "verdict": "true_positive" | "false_positive",
  "confidence": <0.0-1.0>,
  "verdict_reason": "why this construct is/isn't a real issue — required",
  "ai_fix": "<remediation guidance, only when verdict is true_positive>"
}, ...]"""


def build_group_confirm_batch_prompt(
    *,
    entries: Sequence[Dict[str, Any]],
    stack_context: str = "",
) -> Tuple[str, str]:
    """System + user prompt for one batched confirmation call covering
    len(entries) groups. Candidate metadata for all groups is one compact
    JSON array (no code); each group's representative-occurrence snippet
    follows as a separately labeled block ("Pattern <group_index> — <file>:"),
    so index alignment between request and response never depends on JSON
    array order in the model's response."""
    candidates = []
    context_blocks = []
    for entry in entries:
        representative = entry["representative"]
        rule = entry["rule"]
        occurrence_paths = entry["occurrence_paths"]
        shown = list(occurrence_paths[:10])
        extra = len(occurrence_paths) - len(shown)
        occurrence_note = ", ".join(shown) + (f", +{extra} more" if extra > 0 else "")
        candidates.append({
            "group_index": entry["group_index"],
            "rule_id": representative.get("rule_id"),
            "title": (rule.title if rule else representative.get("title")) or "",
            "description": (rule.description if rule else "") or "",
            "cwe": (rule.cwe if rule else representative.get("cwe")) or "",
            "severity": (rule.severity if rule else representative.get("severity")) or "LOW",
            "owasp": (rule.owasp if rule else representative.get("owasp_category")) or "",
            "matched_text": representative.get("matched_text") or "",
            "occurrence_count": len(occurrence_paths),
            "occurrence_files": occurrence_note,
        })
        line = int(representative.get("line") or 1)
        context = build_code_context(entry["source_text"], line, representative.get("matched_text") or "")
        context_blocks.append(
            f"Pattern {entry['group_index']} — {representative.get('file_path')}:\n```\n{context}\n```"
        )
    system = (
        f"{_GROUP_CONFIRM_BATCH_SYSTEM}\n\n"
        f"Tech stack: {stack_context or 'unknown'}\n"
        f"OWASP Top 10:2021 categories: {', '.join(OWASP_TOP_10_2021)}"
    )
    user = (
        f"Patterns ({len(entries)}):\n{json.dumps(candidates, indent=2)}\n\n"
        + "\n\n".join(context_blocks) + "\n\n"
        + f"{_GROUP_BATCH_RESPONSE_SCHEMA}\n"
    )
    return system, user


def confirm_finding_group_batch(
    *,
    entries: Sequence[Dict[str, Any]],
    stack_context: str = "",
    usage: Optional[Dict[str, Any]] = None,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    call_llm_fn: Callable[..., str] = call_llm,
) -> Dict[int, Dict[str, Any]]:
    """One LLM call to TP/FP-confirm len(entries) groups at once, falling back
    to a per-group confirm_finding_group call for anything the batch didn't
    resolve. Returns
    {group_index: {"verdict", "confidence", "verdict_reason", "ai_fix", "error"}}
    for every entry.

    A batch call that raises, or whose response is entirely unparseable even
    after one retry, does not leave its groups unverified outright — each
    entry gets its own confirm_finding_group call instead (that path has its
    own internal retry). Likewise, a response that parses but is missing some
    group_index values falls back per-group for just those. Only an entry
    whose fallback call *also* fails ends up unverified with `error` set —
    the batch is purely a cost optimization, never a coverage reduction.
    """
    system, user = build_group_confirm_batch_prompt(entries=entries, stack_context=stack_context)
    max_tokens = max(512, 160 * len(entries))

    def _call(prompt: str) -> str:
        with _INFLIGHT:
            return call_llm_fn(
                system, prompt,
                max_tokens=max_tokens, temperature=0.0,
                usage=usage, step="group_confirm_triage_findings",
                provider=llm_provider, model=llm_model,
            )

    results: Dict[int, Dict[str, Any]] = {}
    unresolved: List[Dict[str, Any]] = list(entries)

    try:
        raw_text = _call(user)
        items, err = parse_llm_json_array(raw_text)
        if err and not items:
            retry_user = (
                user
                + "\n\nYour previous response could not be parsed as JSON. "
                "Respond with a valid JSON array — no prose, no markdown fences."
            )
            raw_text = _call(retry_user)
            items, err = parse_llm_json_array(raw_text)

        by_index = {
            item.get("group_index"): item
            for item in items or []
            if isinstance(item, dict) and isinstance(item.get("group_index"), int)
        }
        unresolved = []
        for entry in entries:
            item = by_index.get(entry["group_index"])
            if item is None:
                unresolved.append(entry)
                continue
            results[entry["group_index"]] = _confirm_result_from_item(item)
    except Exception:
        pass  # whole batch failed to call/parse — every entry falls back below

    for entry in unresolved:
        results[entry["group_index"]] = confirm_finding_group(
            representative=entry["representative"], occurrence_paths=entry["occurrence_paths"],
            source_text=entry["source_text"], rule=entry["rule"], stack_context=stack_context,
            usage=usage, llm_provider=llm_provider, llm_model=llm_model, call_llm_fn=call_llm_fn,
        )

    return results


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
                candidates.append(finding)

    groups: Dict[tuple, List[Dict[str, Any]]] = {}
    group_order: List[tuple] = []
    for finding in candidates:
        key = group_key_for_finding(finding)
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
        })
    summaries.sort(key=lambda g: g["occurrence_count"], reverse=True)

    return {
        "candidate_count": len(candidates),
        "group_count": len(group_order),
        "groups": summaries,
        "members_by_key": groups,
        "group_order": group_order,
    }


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
) -> Dict[str, Any]:
    """Group unverified findings (via `group_unverified_findings`) and confirm
    each group with an LLM call, mutating every member finding dict in place.

    `group_cap`, when set, confirms only the top-N groups by occurrence count
    (the biggest collapses first) and leaves the rest unverified — a backstop
    against repos with hundreds of groups. `groups_per_call` batches multiple
    groups into one LLM call (1 = today's one-call-per-group behavior) to
    amortize the shared system-prompt/OWASP-label overhead across a batch.

    `verdict_updates_writer(file_path, updates)`, when given, is called once
    per distinct file among all group members with the per-finding update
    dicts ({rule_id, line, verdict, confidence, verdict_reason, ai_fix}) so a
    caller can persist the change onto already-written DB rows.
    """
    grouping = group_unverified_findings(file_results, severities=severities)
    groups = grouping["members_by_key"]
    by_occurrence = sorted(grouping["group_order"], key=lambda k: len(groups[k]), reverse=True)
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

    def _occurrence_paths(members: List[Dict[str, Any]]) -> List[str]:
        occurrence_paths: List[str] = []
        seen: Set[str] = set()
        for m in members:
            p = m.get("file_path") or ""
            if p and p not in seen:
                seen.add(p)
                occurrence_paths.append(p)
        return occurrence_paths

    def _apply_result(members: List[Dict[str, Any]], result: Dict[str, Any]) -> None:
        if result.get("error") is not None:
            return
        for m in members:
            m["verdict"] = result["verdict"]
            m["confidence"] = result["confidence"]
            m["verdict_reason"] = (
                f"{result['verdict_reason']} "
                f"(confirmed via grouped review of {len(members)} occurrence(s) of this pattern)"
            )
            if result["verdict"] == "true_positive" and result.get("ai_fix"):
                m["ai_fix"] = result["ai_fix"]

    def _run(key: tuple) -> Dict[str, Any]:
        members = groups[key]
        representative = members[0]
        occurrence_paths = _occurrence_paths(members)
        source_text = _text_for(representative.get("file_path") or "")
        result = confirm_finding_group(
            representative=representative, occurrence_paths=occurrence_paths,
            source_text=source_text, rule=rules_by_id.get(representative.get("rule_id") or ""),
            stack_context=stack_context, usage=usage,
            llm_provider=llm_provider, llm_model=llm_model, call_llm_fn=call_llm_fn,
        )
        _apply_result(members, result)
        return {"key": key, "members": members, **result}

    def _run_batch(batch_keys: List[tuple]) -> List[Dict[str, Any]]:
        entries = []
        for i, key in enumerate(batch_keys):
            members = groups[key]
            representative = members[0]
            entries.append({
                "group_index": i,
                "representative": representative,
                "occurrence_paths": _occurrence_paths(members),
                "source_text": _text_for(representative.get("file_path") or ""),
                "rule": rules_by_id.get(representative.get("rule_id") or ""),
            })
        results_by_index = confirm_finding_group_batch(
            entries=entries, stack_context=stack_context, usage=usage,
            llm_provider=llm_provider, llm_model=llm_model, call_llm_fn=call_llm_fn,
        )
        batch_outcomes = []
        for i, key in enumerate(batch_keys):
            members = groups[key]
            result = results_by_index[i]
            _apply_result(members, result)
            batch_outcomes.append({"key": key, "members": members, **result})
        return batch_outcomes

    outcomes: List[Dict[str, Any]] = []
    if groups_per_call <= 1:
        if len(confirm_keys) > 1 and group_workers > 1:
            with ThreadPoolExecutor(max_workers=min(group_workers, len(confirm_keys))) as pool:
                outcomes = list(pool.map(_run, confirm_keys))
        else:
            outcomes = [_run(key) for key in confirm_keys]
    else:
        batches = [confirm_keys[i:i + groups_per_call] for i in range(0, len(confirm_keys), groups_per_call)]
        if len(batches) > 1 and group_workers > 1:
            with ThreadPoolExecutor(max_workers=min(group_workers, len(batches))) as pool:
                outcomes = [o for batch_outcomes in pool.map(_run_batch, batches) for o in batch_outcomes]
        else:
            outcomes = [o for batch_keys in batches for o in _run_batch(batch_keys)]

    if verdict_updates_writer is not None:
        updates_by_file: Dict[str, List[Dict[str, Any]]] = {}
        for outcome in outcomes:
            if outcome.get("error") is not None:
                continue
            for m in outcome["members"]:
                path = m.get("file_path") or ""
                updates_by_file.setdefault(path, []).append({
                    "rule_id": m.get("rule_id"),
                    "line": m.get("line"),
                    "verdict": m.get("verdict"),
                    "confidence": m.get("confidence"),
                    "verdict_reason": m.get("verdict_reason"),
                    "ai_fix": m.get("ai_fix"),
                })
        for path, updates in updates_by_file.items():
            verdict_updates_writer(path, updates)

    if on_group is not None:
        for outcome in outcomes:
            on_group(outcome)

    tp = sum(1 for o in outcomes if o.get("verdict") == "true_positive")
    fp = sum(1 for o in outcomes if o.get("verdict") == "false_positive")
    errors = sum(1 for o in outcomes if o.get("error") is not None)
    return {
        "candidate_count": grouping["candidate_count"],
        "group_count": len(by_occurrence),
        "confirm_group_count": len(confirm_keys),
        "skipped_group_count": len(skipped_keys),
        "tp_group_count": tp,
        "fp_group_count": fp,
        "error_group_count": errors,
        "confirmed_finding_count": sum(len(o["members"]) for o in outcomes if o.get("error") is None),
    }
