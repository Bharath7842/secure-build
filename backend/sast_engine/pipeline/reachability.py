"""reachability.py — source->sink paths as evidence for other tiers' findings.

flows.sc reports every source→sink path it finds, but only the top
FLOW_VERIFY_CAP become verified flows, and single-file paths in deep-scanned
files are dropped before verification (joern_flows.flows_from_joern). The
tree-sitter call graph likewise caps its flows. This module keeps *all* of
them as a sink index so a regex, deep-scan or Joern-query finding at a sink
line can carry the path that reaches it.

Two strengths of evidence:
- Joern (STATUS_PATH / STATUS_SANITIZED): an expression-level taint path — this
  request value reaches this argument.
- Call graph (STATUS_ENTRY_REACHABLE): a method-level chain — an entry point
  calls down to the method holding this sink. It doesn't show which value
  reaches the argument, so it is context, never a confidence boost.

Evidence only ever adds: a finding with no path keeps its verdict and its
confidence, because neither analysis models every framework's sources. An
unsanitized Joern path raises a true positive's confidence to
REACHABLE_CONFIDENCE_FLOOR; anything weaker is attached but raises nothing.
"""

from __future__ import annotations

import re
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Tuple

# No pipeline imports: llm_file_scan imports this module, and joern_flows ->
# call_graph -> llm_file_scan would make that a cycle. _norm and _locations
# mirror joern_flows' helpers of the same name.

STATUS_PATH = "path"
STATUS_SANITIZED = "sanitized_path"
STATUS_ENTRY_REACHABLE = "entry_reachable"
# Lower sorts first: a value-level path beats one through a sanitizer, which
# beats a method-level call chain.
_STATUS_RANK = {STATUS_PATH: 0, STATUS_SANITIZED: 1, STATUS_ENTRY_REACHABLE: 2}
REACHABLE_CONFIDENCE_FLOOR = 0.9
LINE_TOLERANCE = 2
# A long path is kept as its first and last steps; the source and the sink
# are what a reviewer reads, the middle is mostly local reassignments.
MAX_PATH_STEPS = 12
_HEAD_STEPS = 3

# taint_spec.json sink kind -> CWEs a finding at that sink can describe.
# tests/test_reachability.py checks every kind in kind_order has an entry.
SINK_KIND_CWES: Dict[str, FrozenSet[str]] = {
    "sql": frozenset({"89"}),
    "jpa": frozenset({"89", "564"}),
    "jdbc_template": frozenset({"89"}),
    "eval": frozenset({"94", "95", "917"}),
    "command": frozenset({"77", "78", "88"}),
    "ssrf": frozenset({"918"}),
    "ldap": frozenset({"90"}),
    "deser": frozenset({"502"}),
    "xxe": frozenset({"611", "776"}),
    "xss": frozenset({"79", "80"}),
    "reflect": frozenset({"470"}),
    "files": frozenset({"22", "23", "36", "73"}),
    "redirect": frozenset({"601"}),
    "header": frozenset({"113", "644"}),
    "response_body": frozenset({"79", "209"}),
    "log": frozenset({"117", "93"}),
}

_CWE_RE = re.compile(r"\d+")

SinkIndex = Dict[Tuple[str, int], List[Dict[str, Any]]]


def _norm(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def _locations(raw: Any) -> List[Dict[str, Any]]:
    return [
        {"file": _norm(str(item.get("file") or "")), "line": int(item.get("line") or -1),
         "code": str(item.get("code") or "")[:200]}
        for item in (raw or []) if isinstance(item, dict)
    ]


def cwe_number(cwe: Any) -> Optional[str]:
    """"CWE-89", "89", "CWE-89: SQL Injection" -> "89"."""
    m = _CWE_RE.search(str(cwe or ""))
    return m.group(0) if m else None


def _step(element: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "file": _norm(str(element.get("file") or "")),
        "line": int(element.get("line") or -1),
        "method": str(element.get("method") or ""),
        "code": str(element.get("code") or "")[:200],
    }


def _compact(path: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if len(path) <= MAX_PATH_STEPS:
        return path
    return path[:_HEAD_STEPS] + path[-(MAX_PATH_STEPS - _HEAD_STEPS):]


def evidence_from_raw(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """One flows.sc flow -> an evidence dict, or None when it has no usable
    file/line (Joern's synthetic <empty>/<unknown> nodes)."""
    elements = [
        e for e in (raw.get("elements") or [])
        if isinstance(e, dict) and e.get("file") and not str(e.get("file")).startswith("<")
    ]
    path = [_step(e) for e in elements]
    path = [s for s in path if s["file"] and s["line"] > 0]
    if not path:
        return None
    sanitizers = _locations(raw.get("sanitizers"))
    return {
        "status": STATUS_SANITIZED if sanitizers else STATUS_PATH,
        "sink_kind": str(raw.get("sink_kind") or "unknown"),
        "sink_code": str(raw.get("sink_code") or path[-1]["code"])[:200],
        "source": {k: path[0][k] for k in ("file", "line", "code")},
        "sink": {k: path[-1][k] for k in ("file", "line", "code")},
        "taint_path": _compact(path),
        "steps_total": len(path),
        "sanitizers": sanitizers,
        "guards": _locations(raw.get("guards")),
    }


def evidence_from_flow(flow: Any) -> Optional[Dict[str, Any]]:
    """Evidence for a verified Joern Flow (call_graph.Flow with taint_path)."""
    path = [s for s in (flow.taint_path or []) if s.get("file") and int(s.get("line") or -1) > 0]
    if not path:
        return None
    return {
        "status": STATUS_SANITIZED if flow.sanitizers else STATUS_PATH,
        "sink_kind": flow.sink_kind,
        "sink_code": flow.hops[-1].label if flow.hops else path[-1].get("code", ""),
        "source": {k: path[0].get(k) for k in ("file", "line", "code")},
        "sink": {k: path[-1].get(k) for k in ("file", "line", "code")},
        "taint_path": _compact(list(path)),
        "steps_total": len(path),
        "sanitizers": list(flow.sanitizers or []),
        "guards": list(flow.guards or []),
    }


def evidence_from_call_graph_flow(flow: Any) -> Optional[Dict[str, Any]]:
    """Evidence for a tree-sitter call-graph Flow: one step per method hop,
    anchored at the call line inside it (the sink call for the last hop)."""
    hops = [h for h in (flow.hops or []) if h.file and int(h.line or -1) > 0]
    if len(hops) < 2:
        return None
    path = [
        {"file": _norm(h.file), "line": int(h.line), "method": h.method, "code": str(h.label or "")[:200]}
        for h in hops
    ]
    return {
        "status": STATUS_ENTRY_REACHABLE,
        "sink_kind": flow.sink_kind,
        "sink_code": path[-1]["code"],
        "source": {k: path[0][k] for k in ("file", "line", "code")},
        "sink": {k: path[-1][k] for k in ("file", "line", "code")},
        "taint_path": _compact(path),
        "steps_total": len(path),
        "sanitizers": [],
        "guards": [],
        "entry_tier": flow.entry_tier,
        "authenticated": bool(flow.authenticated),
    }


def _add(index: SinkIndex, seen: set, ev: Optional[Dict[str, Any]]) -> None:
    if ev is None:
        return
    key = (ev["sink"]["file"], ev["sink"]["line"])
    sig = (key, ev["status"], ev["sink_kind"], ev["source"]["file"], ev["source"]["line"])
    if sig in seen:
        return
    seen.add(sig)
    index.setdefault(key, []).append(ev)


def build_sink_index(
    raw_results: Iterable[Optional[Dict[str, Any]]] = (),
    call_graph_flows: Iterable[Any] = (),
) -> SinkIndex:
    """Index every flows.sc path (one result per CPG) and every call-graph
    flow by (sink file, sink line)."""
    index: SinkIndex = {}
    seen: set = set()
    for result in raw_results:
        for raw in (result or {}).get("flows") or []:
            if isinstance(raw, dict):
                _add(index, seen, evidence_from_raw(raw))
    for flow in call_graph_flows:
        _add(index, seen, evidence_from_call_graph_flow(flow))
    return index


def evidence_rank(evidence: Optional[Dict[str, Any]]) -> int:
    """0 = Joern path, 1 = sanitized Joern path, 2 = call-graph chain, 9 = none."""
    return _STATUS_RANK.get((evidence or {}).get("status"), 9)


def _preference(ev: Dict[str, Any]) -> Tuple[int, int]:
    return (_STATUS_RANK.get(ev["status"], 9), ev.get("steps_total") or 0)


def match(
    finding: Dict[str, Any],
    index: SinkIndex,
    *,
    file_path: Optional[str] = None,
    line_tolerance: int = LINE_TOLERANCE,
) -> Optional[Dict[str, Any]]:
    """Best evidence for `finding`: a path whose sink is in the same file
    within ±line_tolerance lines and whose sink kind fits the finding's CWE.
    A finding without a CWE never matches — the kind check is what keeps a
    log-injection path from vouching for a SQL finding on the next line."""
    cwe = cwe_number(finding.get("cwe"))
    if not cwe or not index:
        return None
    path = _norm(str(file_path or finding.get("file_path") or ""))
    try:
        line = int(finding.get("line") or -1)
    except (TypeError, ValueError):
        return None
    if not path or line <= 0:
        return None
    candidates = [
        ev
        for delta in range(-line_tolerance, line_tolerance + 1)
        for ev in index.get((path, line + delta), ())
        if cwe in SINK_KIND_CWES.get(ev["sink_kind"], frozenset())
    ]
    return min(candidates, key=_preference) if candidates else None


def apply_confidence(finding: Dict[str, Any]) -> bool:
    """Raise a true positive's confidence when an unsanitized path reaches it.
    Never lowers anything and never touches false_positive or unverified.
    Returns True when the confidence changed."""
    evidence = finding.get("reachability") or {}
    if finding.get("verdict") != "true_positive" or evidence.get("status") != STATUS_PATH:
        return False
    current = finding.get("confidence")
    try:
        current = float(current) if current is not None else 0.0
    except (TypeError, ValueError):
        current = 0.0
    if current >= REACHABLE_CONFIDENCE_FLOOR:
        return False
    finding["confidence"] = REACHABLE_CONFIDENCE_FLOOR
    return True


def corroborate_file_results(
    file_results: Iterable[Dict[str, Any]],
    index: SinkIndex,
) -> Dict[str, List[Dict[str, Any]]]:
    """Attach evidence to every matching finding in a tier's `files` list, in
    place, and raise confidence where apply_confidence allows. Findings that
    already carry evidence (Joern flow findings) are left alone.

    Returns {file_path: [{rule_id, line, reachability, confidence}]} for the
    findings that changed, ready for a DB update writer."""
    updates: Dict[str, List[Dict[str, Any]]] = {}
    for file_result in file_results:
        rel = file_result.get("file_path") or ""
        for finding in file_result.get("findings") or []:
            if finding.get("reachability"):
                continue
            ev = match(finding, index, file_path=finding.get("file_path") or rel)
            if ev is None:
                continue
            finding["reachability"] = ev
            apply_confidence(finding)
            updates.setdefault(finding.get("file_path") or rel, []).append({
                "rule_id": finding.get("rule_id"),
                "line": finding.get("line"),
                "reachability": ev,
                "confidence": finding.get("confidence"),
            })
    return updates


def render_evidence(evidence: Dict[str, Any]) -> str:
    """Prompt text for one evidence dict (group confirmation)."""
    steps = evidence.get("taint_path") or []
    elided = (evidence.get("steps_total") or len(steps)) - len(steps)
    if evidence.get("status") == STATUS_ENTRY_REACHABLE:
        chain = "\n".join(
            f"  {s.get('method', '')} -> {s.get('code', '')}  ({s.get('file', '')}:{s.get('line', '')})"
            for s in steps
        )
        auth = "authenticated" if evidence.get("authenticated") else "no auth annotation seen"
        return "\n".join([
            f"Call-graph evidence ({evidence.get('sink_kind')} sink, {auth}) — an entry point "
            "calls down to this location through these methods. Method level only: it does "
            "not show whether request input reaches the sink's argument:",
            chain + (f"\n  ... {elided} intermediate step(s) omitted" if elided > 0 else ""),
        ])
    chain = "\n".join(
        f"  {s.get('code', '')}  ({s.get('file', '')}:{s.get('line', '')})" for s in steps
    )
    lines = [
        f"Dataflow evidence (Joern, {evidence.get('sink_kind')} sink) — a request-controlled "
        "value reaches this location along this path. It proves reachability for this "
        "occurrence only; a listed sanitizer or guard may still make it safe:",
        chain + (f"\n  ... {elided} intermediate step(s) omitted" if elided > 0 else ""),
    ]
    for label, key in (("Sanitizer calls on the path", "sanitizers"),
                       ("Conditions the path depends on", "guards")):
        items = evidence.get(key) or []
        if items:
            lines.append(label + ": " + "; ".join(
                f"{i.get('code', '')} ({i.get('file', '')}:{i.get('line', '')})" for i in items[:5]
            ))
    return "\n".join(lines)
