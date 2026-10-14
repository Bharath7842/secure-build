"""Search seeds for the hunt toolbox, derived from joern/taint_spec.json.

The taint spec is the single source of truth for which calls are sources,
sinks and sanitizers per sink kind (Joern and call_graph rank by the same
kinds). Here each entry becomes an rg-compatible *textual* pattern. These are
navigation aids — "where might the sinks be" — never proof: a textual match
cannot see the receiver type, so the validator only accepts sink/source
evidence the agent then read or the call graph resolved.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Sequence

TAINT_SPEC_PATH = Path(__file__).resolve().parents[2] / "joern" / "taint_spec.json"

# Java-oriented hints on top of the spec: kinds the spec has no call-level
# entry for, and the configuration-shaped hypotheses (secrets, crypto,
# access control) that start from declarations rather than calls.
EXTRA_SINK_PATTERNS: Dict[str, List[str]] = {
    "log": [r"\b(?:log|logger|LOG|LOGGER)\s*\.\s*(?:trace|debug|info|warn|error|fatal)\s*\("],
    "response_body": [
        r"ResponseEntity\s*\.\s*(?:ok|status|badRequest|internalServerError)\s*\(",
        r"new\s+ResponseEntity\s*<",
        r"\.body\s*\(",
    ],
    "header": [r"\.(?:setHeader|addHeader|addCookie)\s*\("],
    "crypto": [
        r"Cipher\s*\.\s*getInstance\s*\(",
        r"MessageDigest\s*\.\s*getInstance\s*\(",
        r"new\s+(?:Random|SecretKeySpec|IvParameterSpec|DESKeySpec)\s*\(",
    ],
    "secret": [
        r"(?i)(?:password|passwd|secret|api[_-]?key|token)\w*\s*[:=]\s*\"",
    ],
    "authz": [
        r"@(?:PreAuthorize|PostAuthorize|Secured|RolesAllowed|PermitAll|DenyAll)\b",
        r"\.(?:requestMatchers|antMatchers|mvcMatchers|authorizeRequests|authorizeHttpRequests|permitAll)\s*\(",
    ],
    "csrf": [r"\.csrf\s*\("],
}

ENTRY_ANNOTATION_PATTERN = r"@(?:Get|Post|Put|Delete|Patch|Request)Mapping\b|@(?:GET|POST|PUT|DELETE|PATCH|Path)\b|@WebMethod\b"


@lru_cache(maxsize=1)
def load_taint_spec(path: Optional[str] = None) -> Dict:
    spec_path = Path(path) if path else TAINT_SPEC_PATH
    try:
        return json.loads(spec_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"sources": {}, "sinks": [], "sanitizers": [], "kind_order": []}


def _names(alternation: str) -> List[str]:
    """Method names from a spec `name` alternation, dropping regex-only
    entries rg can't use as literal call names."""
    out: List[str] = []
    for raw in (alternation or "").split("|"):
        name = raw.strip().replace("\\$", "$")
        if name and name != "<init>" and re.fullmatch(r"[$\w]+", name):
            out.append(name)
    return out


def _type_names(full_name: str) -> List[str]:
    """Simple class names in a spec full_name regex — the capitalized tokens,
    since package segments are lowercase: `java\\.io\\.(File|FileReader)\\..*`
    -> [File, FileReader]."""
    return list(dict.fromkeys(re.findall(r"\b[A-Z][A-Za-z0-9]+\b", full_name or "")))


# Method names too common to search for on their own: alone they match half
# of any codebase, so they are searched as a `.name(` method call instead.
GENERIC_NAMES = frozenset({
    "append", "body", "command", "copy", "debug", "delete", "error", "exception", "exec",
    "execute", "format", "get", "info", "invoke", "log", "lookup", "move", "of", "ok",
    "parse", "print", "printf", "println", "query", "read", "resolve", "search", "send",
    "start", "status", "trace", "transform", "update", "warn", "warning", "write",
})

# Precise Java idioms searched before the spec-derived patterns: the textual
# form of a sink whose method name alone is generic.
JAVA_IDIOMS: Dict[str, List[str]] = {
    "command": [r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\("],
    "files": [
        r"\b(?:Paths\s*\.\s*get|Path\s*\.\s*of)\s*\(",
        r"\bFiles\s*\.\s*(?:copy|delete|move|write|writeString|readString|readAllBytes|newInputStream|newOutputStream|newBufferedReader|newBufferedWriter)\s*\(",
    ],
    "xss": [r"getWriter\s*\(\s*\)\s*\.\s*(?:print|println|write|append|format|printf)\s*\("],
    "reflect": [r"\bClass\s*\.\s*forName\s*\("],
    "xxe": [r"\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory)\s*\.\s*newInstance\s*\("],
}


def _call_pattern(names: Sequence[str]) -> str:
    return r"\b(?:" + "|".join(sorted(set(names))) + r")\s*\("


def _entry_patterns(names: Sequence[str]) -> List[str]:
    specific = [n for n in names if n not in GENERIC_NAMES]
    generic = [n for n in names if n in GENERIC_NAMES]
    out: List[str] = []
    if specific:
        out.append(_call_pattern(specific))
    if generic:
        out.append(r"\.\s*(?:" + "|".join(sorted(set(generic))) + r")\s*\(")
    return out


def _is_java_entry(entry: Dict) -> bool:
    full = entry.get("full_name") or ""
    return any(token in full for token in ("java", "jakarta", "springframework", "persistence", "hibernate", "RestTemplate", "xml", "XML", "expression"))


@lru_cache(maxsize=4)
def sink_patterns(java_only: bool = True) -> Dict[str, List[str]]:
    spec = load_taint_spec()
    patterns: Dict[str, List[str]] = {}
    for entry in spec.get("sinks") or []:
        if java_only and not _is_java_entry(entry):
            continue
        kind = entry.get("kind") or "other"
        bucket = patterns.setdefault(kind, list(JAVA_IDIOMS.get(kind, [])) if java_only else [])
        bucket.extend(_entry_patterns(_names(entry.get("name") or "")))
        if "<init>" in (entry.get("name") or ""):
            types = _type_names(entry.get("full_name") or "")
            if types:
                bucket.append(r"new\s+(?:" + "|".join(types) + r")\s*\(")
    for kind, extra in EXTRA_SINK_PATTERNS.items():
        patterns.setdefault(kind, []).extend(extra)
    return {k: list(dict.fromkeys(v)) for k, v in patterns.items() if v}


@lru_cache(maxsize=1)
def source_patterns() -> List[str]:
    sources = load_taint_spec().get("sources") or {}
    out: List[str] = []
    params = sources.get("param_annotations")
    if params:
        out.append(r"@(?:" + params + r")\b")
    accessor_names: List[str] = []
    for entry in sources.get("accessor_calls") or []:
        accessor_names.extend(_names(entry.get("name") or ""))
    if accessor_names:
        out.append(r"\.(?:" + "|".join(sorted(set(accessor_names))) + r")\s*\(")
    return out


@lru_cache(maxsize=1)
def sanitizer_patterns() -> Dict[str, List[str]]:
    by_kind: Dict[str, List[str]] = {}
    for entry in load_taint_spec().get("sanitizers") or []:
        names = _names(entry.get("name") or "")
        if not names:
            continue
        pattern = _call_pattern(names)
        for kind in entry.get("kinds") or []:
            by_kind.setdefault(kind, []).append(pattern)
    # Parameter binding is the SQL sanitizer the spec can't express as a call.
    by_kind.setdefault("sql", []).append(r"\.set(?:String|Int|Long|Object)\s*\(\s*\d+\s*,")
    return {k: list(dict.fromkeys(v)) for k, v in by_kind.items()}


def known_sink_kinds() -> List[str]:
    order = list(load_taint_spec().get("kind_order") or [])
    for kind in sink_patterns():
        if kind not in order:
            order.append(kind)
    return order
