"""derive_rules.py — runtime RegexRules from this scan's analysis.

Pass A (no LLM): project methods that contain a typed Java sink become
Kind-A wrapper patterns (``\\bname\\s*\\(``). Pass B (one LLM call): extra
source/sink API patterns for the detected stack. Both are merged onto the
static ``rules/`` catalog — never written back to disk, never a replacement.

Catalog rules always win on id or normalized-pattern collision.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from llm_client import call_llm, parse_llm_json_array

from pipeline.call_graph_common import GraphAdapter
from pipeline.owasp_map import owasp_for_rule
from pipeline.regex_scan import RegexRule

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
    "- Do not clone or restate any catalog id already listed.\n"
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
    if not re.search(r"[A-Za-z_]", pattern):
        return "no_identifier"
    return None


def _sanitize_id_fragment(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "-", name).strip("-")
    return cleaned or "unnamed"


def wrappers_from_graph(graph: Optional[GraphAdapter]) -> List[Dict[str, Any]]:
    """Pass A: one Kind-A rule dict per distinct (wrapper name, sink kind),
    most severe sink kind first, then by name (a stable order keeps the
    derived set — and the prompts that embed it — identical across reruns)."""
    if graph is None:
        return []
    language = getattr(graph, "language", "java") or "java"
    generic_names = _GENERIC_NAMES_BY_LANG.get(language, _GENERIC_NAMES_BY_LANG["java"])
    sink_method_names = _SINK_METHOD_NAMES_BY_LANG.get(language, _SINK_METHOD_NAMES_BY_LANG["java"])
    seen: Set[Tuple[str, str]] = set()
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
        key = (name.lower(), kind)
        if key in seen:
            continue
        seen.add(key)
        cwe = _SINK_KIND_CWE.get(kind, "CWE-89")
        severity = _SINK_KIND_SEVERITY.get(kind, "MEDIUM")
        raw.append({
            "id": f"runtime-sink-{kind}-{_sanitize_id_fragment(name)}",
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
        })
    raw.sort(key=lambda r: (_SINK_KIND_RANK.get(r["sink_kind"], len(_SINK_KIND_RANK)), r["wrapper_name"].lower()))
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
    if not norm or norm in catalog_patterns or norm in seen_patterns:
        if dropped is not None:
            dropped.append("duplicate_pattern")
        return None
    entry["derived"] = True
    try:
        rule = RegexRule(entry)
    except (re.error, KeyError, TypeError):
        if dropped is not None:
            dropped.append("compile_error")
        return None
    seen_ids.add(rule.id)
    seen_patterns.add(_norm_pattern(rule.pattern))
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
        rule = compile_derived_rule(
            raw,
            catalog_ids=catalog_ids,
            catalog_patterns=catalog_patterns,
            seen_ids=seen_ids,
            seen_patterns=seen_patterns,
            dropped=dropped,
        )
        if rule is not None:
            out.append(rule)
    return out


def _coerce_rule_items(items: Iterable[Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for item in items:
        if isinstance(item, dict) and item.get("pattern"):
            out.append(item)
    return out


def _ensure_runtime_llm_id(raw: Dict[str, Any], index: int) -> Dict[str, Any]:
    entry = dict(raw)
    rid = str(entry.get("id") or "").strip()
    if not rid.startswith("runtime-llm-"):
        suffix = _sanitize_id_fragment(rid) if rid else str(index)
        entry["id"] = f"runtime-llm-{suffix}"
    entry["derived"] = True
    return entry


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


def llm_derive_rules(
    *,
    stack_context: str,
    frameworks: Sequence[str],
    surfaces: Sequence[str],
    catalog_ids: Sequence[str],
    pass_a_names: Sequence[str],
    sample_types: Sequence[str],
    remaining_slots: int,
    usage: Optional[Dict[str, Any]] = None,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    call_llm_fn: Callable[..., str] = call_llm,
) -> List[Dict[str, Any]]:
    """Pass B: one LLM call. Empty on parse failure after a single retry."""
    if remaining_slots <= 0:
        return []
    remaining_slots = min(remaining_slots, PASS_B_MAX_RULES_PER_CALL)
    max_tokens = min(
        PASS_B_MAX_TOKENS_CEILING,
        remaining_slots * PASS_B_TOKENS_PER_RULE + PASS_B_TOKEN_HEADROOM,
    )
    user = (
        f"Tech stack: {stack_context or 'unknown'}\n"
        f"Frameworks: {', '.join(frameworks) or 'none'}\n"
        f"Active surfaces: {', '.join(surfaces) or 'none'}\n"
        f"Existing catalog ids (do not clone): {', '.join(catalog_ids) or 'none'}\n"
        f"Already-derived wrapper names: {', '.join(pass_a_names) or 'none'}\n"
        f"Project type names (sample): {', '.join(sample_types) or 'none'}\n"
        f"Return at most {remaining_slots} objects.\n\n"
        "Each object fields: id, title, description, cwe, severity, owasp, "
        "languages (array), frameworks (array), pattern.\n"
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
    coerced = _coerce_rule_items(items)
    return [_ensure_runtime_llm_id(entry, i) for i, entry in enumerate(coerced, start=1)]


def derive_runtime_rules(
    *,
    graph: Optional[GraphAdapter] = None,
    static_rules: Sequence[RegexRule] = (),
    stack_context: str = "",
    frameworks: Optional[Sequence[str]] = None,
    surfaces: Optional[Sequence[str]] = None,
    use_llm: bool = False,
    usage: Optional[Dict[str, Any]] = None,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    max_rules: int = DEFAULT_MAX_DERIVED,
    call_llm_fn: Callable[..., str] = call_llm,
    dropped: Optional[List[str]] = None,
) -> List[RegexRule]:
    """Pass A then Pass B, catalog-preserving merge, capped at `max_rules`.

    Pass A is preferred when trimming. Pass B is skipped when `use_llm` is false.

    `dropped`, when passed, ends up holding one reason string per candidate
    that didn't make the final compiled set — reflects whichever pass(es)
    actually produced the returned rules, not double-counted across passes.
    """
    cap = max(0, int(max_rules))
    pass_a_raw = wrappers_from_graph(graph)
    pass_a_dropped: List[str] = []
    compiled = compile_derived_rules(pass_a_raw, static_rules, cap=cap, dropped=pass_a_dropped)
    if not use_llm or len(compiled) >= cap:
        if dropped is not None:
            dropped.extend(pass_a_dropped)
        return compiled

    catalog_ids = [r.id for r in static_rules]
    pass_a_names = [str(raw.get("wrapper_name") or raw.get("id")) for raw in pass_a_raw]
    try:
        pass_b_raw = llm_derive_rules(
            stack_context=stack_context,
            frameworks=list(frameworks or []),
            surfaces=list(surfaces or []),
            catalog_ids=catalog_ids,
            pass_a_names=pass_a_names,
            sample_types=sample_type_names(graph),
            remaining_slots=cap - len(compiled),
            usage=usage,
            llm_provider=llm_provider,
            llm_model=llm_model,
            call_llm_fn=call_llm_fn,
        )
    except Exception:  # noqa: BLE001 — derive must not fail the scan
        if dropped is not None:
            dropped.extend(pass_a_dropped)
        return compiled
    combined_raw = pass_a_raw + pass_b_raw
    return compile_derived_rules(combined_raw, static_rules, cap=cap, dropped=dropped)
