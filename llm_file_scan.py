"""llm_file_scan.py — LLM-primary detect+triage for CRITICAL-risk files.

The LLM owns detection here, not `regex_scan.py` — `regex_rules.json` is used
only as a rule *catalog* (title/cwe/severity/owasp/pattern as guidance), never
executed as a pre-pass or a gate. Every CRITICAL file gets scanned regardless
of whether any regex pattern would have matched.

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
from .regex_scan import RegexRule, rules_for_prompt, _SQL_CONCAT_CATALOG_IDS

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
MAX_INFLIGHT_LLM_CALLS = 6
DEFAULT_FILE_WORKERS = 4
DEFAULT_CHUNK_WORKERS = 3

# Findings below this confidence are dropped when they are also unevidenced
# generic-catalog echoes. Evidenced findings survive at any confidence.
UNEVIDENCED_CONFIDENCE_FLOOR = 0.6

_INFLIGHT = threading.Semaphore(MAX_INFLIGHT_LLM_CALLS)
_USAGE_LOCK = threading.Lock()
_CALLBACK_LOCK = threading.Lock()

# --- evidence / noise patterns ---------------------------------------------

_RESULTSET_READ_RE = re.compile(
    r"\b(?:rs|resultSet|result_set)\s*\.\s*get(?:String|Int|Long|Object|BigDecimal|Date)\s*\(",
    re.IGNORECASE,
)
_SQL_BUILD_RE = re.compile(
    r"\b(?:SELECT|INSERT|UPDATE|DELETE|MERGE)\b.*?(?:\+|\|\||\.format\s*\(|String\.format|%s|\$\{|f\")",
    re.IGNORECASE | re.DOTALL,
)

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
    """Extension -> regex_rules.json language tag (for catalog filtering and
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


# --- prompt -----------------------------------------------------------------

_SYSTEM_HEAD = (
    "You are a senior application security engineer performing manual source-code "
    "review. You are shown one code chunk from a CRITICAL-risk file, a skeleton map "
    "of the rest of the file, a catalog of known vulnerability patterns as guidance "
    "(not a checklist to match verbatim), and the project's tech-stack context.\n\n"
    "Your job is to find real, concrete security issues — especially where untrusted "
    "input reaches SQL, OS commands, LDAP, XPath, deserialization, file paths, "
    "template engines, or the DOM.\n\n"
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
    "- Use the catalog to calibrate severity/CWE/OWASP vocabulary, but do not limit "
    "yourself to it — flag anything else that is a genuine vulnerability.\n"
    "- Report the line number exactly as shown in the numbered code. Never invent a "
    "line number, and never report a line outside the chunk shown.\n"
    "- For every candidate issue decide true_positive or false_positive and always "
    "give a verdict_reason, even for false positives.\n\n"
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
    fields = ("id", "title", "cwe", "severity", "owasp") + (("pattern",) if keep_pattern else ())
    return [{k: rule[k] for k in fields if k in rule} for rule in catalog]


# --- normalization / anchoring / dedupe -------------------------------------

_VALID_VERDICTS = {"true_positive", "false_positive"}
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
    }


def _dedupe_key(finding: Dict[str, Any]) -> tuple:
    """Group by line plus a coarse topic so the same issue reported under two
    different rule_ids across an overlap region collapses into one row."""
    title = re.sub(r"[^a-z]+", " ", finding["title"].lower()).strip()
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


def should_publish_finding(finding: Dict[str, Any], context_text: str = "") -> bool:
    """Evidence-based suppression.

    The previous revision dropped every finding whose rule_id was a generic SQL
    concat catalog id, which deleted real SQL injections that happened to be
    tagged with one. Here a noisy id only suppresses when there is *also* no
    evidence: no query construction anywhere in the context window, no named
    untrusted source, and low confidence.

    `context_text` should be the enriched source window, not the model's
    truncated snippet — a sink-only snippet whose query is built 20 lines above
    otherwise looks unevidenced when it is not."""
    snippet = (finding.get("snippet") or "").strip()
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


def finalize_findings(findings: List[Dict[str, Any]], source_text: str) -> List[Dict[str, Any]]:
    """Enrich snippets with real source context, *then* apply suppression
    against that context. Order matters: judging a sink-only snippet before
    enrichment is what caused genuine injections to be filtered out."""
    out: List[Dict[str, Any]] = []
    for finding in findings:
        context = build_code_context(
            source_text, finding["line"], finding.get("snippet") or "",
        )
        if not should_publish_finding(finding, context):
            continue
        enriched = dict(finding)
        enriched["snippet"] = context
        out.append(enriched)
    return out


# --- LLM plumbing -----------------------------------------------------------

def _merge_usage(target: Optional[Dict[str, Any]], part: Dict[str, Any]) -> None:
    """Merge a per-call usage dict into the shared one under a lock. Each call
    gets its own dict so concurrent `call_llm` invocations never race."""
    if target is None or not part:
        return
    with _USAGE_LOCK:
        for key, value in part.items():
            existing = target.get(key)
            if isinstance(value, (int, float)) and isinstance(existing, (int, float)):
                target[key] = existing + value
            elif isinstance(value, list) and isinstance(existing, list):
                existing.extend(value)
            else:
                target[key] = value


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
) -> Dict[str, Any]:
    """Scan one chunk. Returns {"findings": [...], "error": str|None}.

    A malformed JSON response gets one retry with an explicit repair nudge; if
    it still fails the error is returned rather than silently yielding zero
    findings, which is how the old version lost whole chunks."""
    system = system_prompt or build_system_prompt(catalog, stack_context)
    user = build_user_prompt(
        file_path=file_path, chunk_text=chunk["text"],
        start_line=chunk["start_line"], skeleton=skeleton,
    )

    def _call(prompt: str) -> str:
        local_usage: Dict[str, Any] = {}
        with _INFLIGHT:
            text = call_llm_fn(
                system, prompt,
                max_tokens=4096, temperature=0.0,
                usage=local_usage, step="scan_critical_files",
                provider=llm_provider, model=llm_model,
            )
        _merge_usage(usage, local_usage)
        return text

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
            source_lines=source_lines,
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
    stack_context: str = "",
    usage: Optional[Dict[str, Any]] = None,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    call_llm_fn: Callable[..., str] = call_llm,
    on_chunk_start: Optional[Callable[[int, int, str], None]] = None,
    chunk_workers: int = DEFAULT_CHUNK_WORKERS,
    catalog: Optional[List[Dict[str, Any]]] = None,
    system_prompt: Optional[str] = None,
) -> Dict[str, Any]:
    text = _read_text(repo_root, rel_path)
    if text is None:
        return {
            "file_path": rel_path, "chunks": 0, "findings": [],
            "tp_count": 0, "fp_count": 0, "read_error": True, "chunk_errors": [],
        }

    lang = lang_for_path(rel_path)
    if catalog is None:
        catalog = trim_catalog(rules_for_prompt(rules, lang, active_frameworks))
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

    merged = finalize_findings(merge_dedupe(all_findings), text)
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
    tp_count = fp_count = 0
    for file_result in file_results:
        for finding in file_result.get("findings", []):
            bucket = by_owasp.setdefault(
                finding["owasp_category"], {"true_positive": 0, "false_positive": 0}
            )
            bucket[finding["verdict"]] = bucket.get(finding["verdict"], 0) + 1
            if finding["verdict"] == "true_positive":
                tp_count += 1
            else:
                fp_count += 1
    return {
        "files_scanned": len(file_results),
        "tp_count": tp_count,
        "fp_count": fp_count,
        "by_owasp_category": by_owasp,
        "chunk_errors": sum(len(r.get("chunk_errors") or []) for r in file_results),
    }


def scan_critical_files(
    *,
    module_plan: Dict[str, Any],
    repo_root: Path,
    rules: List[RegexRule],
    active_frameworks: Optional[Set[str]] = None,
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
) -> Dict[str, Any]:
    """Scans CRITICAL-risk files in `module_plan` — no zero-regex-hit skip gate,
    every file scanned gets a full LLM pass.

    Files and the chunks within them run concurrently, bounded globally by
    MAX_INFLIGHT_LLM_CALLS so nesting the two pools cannot exceed the provider
    rate limit. Set `file_workers=1, chunk_workers=1` for the old strictly
    sequential behaviour.

    `findings_writer(file_path, findings)` is still called once per file (both
    TP and FP rows together) right after that file's findings are merged, so
    persistence stays incremental; callbacks are serialised under a lock, so
    they do not need to be thread-safe themselves, but they arrive in
    completion order rather than plan order. The returned `files` list is
    always in plan order.

    If `module_plan["critical_scan_paths"]` is present (set by
    node_map_modules_and_risk to cap + diversify large CRITICAL sets across
    modules), only those paths are scanned, in that order. Otherwise every
    CRITICAL-risk file is scanned — this keeps direct callers/tests that build
    a bare `module_plan` dict working unchanged."""
    critical_files = [f for f in module_plan.get("files", []) if f.get("risk_level") == "CRITICAL"]
    scan_paths = module_plan.get("critical_scan_paths")
    if scan_paths is not None:
        by_path = {f["path"]: f for f in critical_files}
        critical_files = [by_path[p] for p in scan_paths if p in by_path]
    total = len(critical_files)

    # Catalog + system prompt are stable per language: build each once for the
    # whole tier instead of re-serialising the rule set for every file, and
    # keep the prefix byte-identical so provider prompt caching can hit.
    prompt_cache: Dict[Optional[str], Tuple[List[Dict[str, Any]], str]] = {}
    cache_lock = threading.Lock()

    def _prompt_parts(path: str) -> Tuple[List[Dict[str, Any]], str]:
        lang = lang_for_path(path)
        with cache_lock:
            cached = prompt_cache.get(lang)
            if cached is None:
                catalog = trim_catalog(rules_for_prompt(rules, lang, active_frameworks))
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
            active_frameworks=active_frameworks, stack_context=stack_context,
            usage=usage, llm_provider=llm_provider, llm_model=llm_model,
            call_llm_fn=call_llm_fn, on_chunk_start=_log_chunk_start,
            chunk_workers=chunk_workers, catalog=catalog,
            system_prompt=system_prompt,
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
