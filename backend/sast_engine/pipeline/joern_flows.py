"""joern_flows.py — turn joern/flows.sc output into call_graph.Flow objects.

Unlike call_graph.py's method-level BFS ("A calls B"), every Joern flow is a
real dataflow path: each element is an expression the tainted value passes
through. That path is kept on ``Flow.taint_path`` and shown to the LLM in
flow_verify, so the model checks a concrete argument chain instead of
inferring one from method bodies.

Hops are built by collapsing consecutive path elements in the same method;
bodies are re-read from disk using Joern's method line span, so the slice is
the same "full method body per hop" shape tree-sitter flows produce and
flow_verify needs no Joern-specific branch beyond the taint-path note.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from pipeline.call_graph import _AUTH_ANNOTATIONS, Flow, FlowHop, _SINK_SEVERITY, collapse_flows_by_sink

ENTRY_TIER = "joern"
# Fallback window when Joern has no method end line (some frontends, or a
# module-level Python statement).
_FALLBACK_CONTEXT = 20
# Sink kinds that only Joern reports and that fire on most endpoints of a
# typical web app (any request value logged or returned). They rank behind
# every other kind regardless of cross-file reach, so they only take
# FLOW_VERIFY_CAP slots the injection-class flows didn't need.
_LOW_VALUE_KINDS = frozenset({"log", "response_body", "header"})


def _norm(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def _short_method(full_name: str, name: str) -> str:
    # "com.x.UserDao.find:java.lang.String(java.lang.String)" -> "UserDao.find"
    qualified = (full_name or "").split(":", 1)[0]
    parts = [p for p in qualified.replace("::", ".").split(".") if p]
    if len(parts) >= 2 and parts[-1] == name:
        return f"{parts[-2]}.{name}"
    return name or qualified or "<unknown>"


class _SourceCache:
    def __init__(self, root: Path):
        self.root = root
        self._lines: Dict[str, Optional[List[str]]] = {}

    def lines(self, rel: str) -> Optional[List[str]]:
        if rel not in self._lines:
            try:
                text = (self.root / rel).read_text(encoding="utf-8", errors="replace")
                self._lines[rel] = text.splitlines()
            except OSError:
                self._lines[rel] = None
        return self._lines[rel]


def _hop(group: List[Dict[str, Any]], role: str, label: str, src: _SourceCache) -> Optional[FlowHop]:
    first = group[0]
    rel = _norm(first.get("file") or "")
    lines = src.lines(rel)
    if not rel or lines is None:
        return None
    elem_lines = [int(e.get("line") or -1) for e in group if int(e.get("line") or -1) > 0]
    start = int(first.get("method_line") or -1)
    end = int(first.get("method_line_end") or -1)
    if start <= 0 or end < start:
        anchor = min(elem_lines) if elem_lines else 1
        start = max(1, anchor - _FALLBACK_CONTEXT)
        end = (max(elem_lines) if elem_lines else anchor) + _FALLBACK_CONTEXT
    end = min(end, len(lines))
    start = min(start, max(1, end))
    if role == "sink":
        line = elem_lines[-1] if elem_lines else start
    else:
        line = elem_lines[0] if elem_lines else start
    name = first.get("method") or ""
    full = first.get("method_full_name") or ""
    return FlowHop(
        file=rel,
        method=_short_method(full, name),
        fqcn=full.split(":", 1)[0],
        name=name,
        line=line,
        start_line=start,
        end_line=end,
        body="\n".join(lines[start - 1:end]),
        role=role,
        label=label,
    )


def _group_by_method(elements: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
    groups: List[List[Dict[str, Any]]] = []
    for e in elements:
        key = (_norm(e.get("file") or ""), e.get("method_full_name") or e.get("method"))
        if groups and (_norm(groups[-1][0].get("file") or ""),
                       groups[-1][0].get("method_full_name") or groups[-1][0].get("method")) == key:
            groups[-1].append(e)
        else:
            groups.append([e])
    return groups


def _locations(raw: Any) -> List[Dict[str, Any]]:
    return [
        {"file": _norm(str(item.get("file") or "")), "line": int(item.get("line") or -1),
         "code": str(item.get("code") or "")[:200]}
        for item in (raw or []) if isinstance(item, dict)
    ]


def flow_from_raw(raw: Dict[str, Any], src: _SourceCache) -> Optional[Flow]:
    elements = [e for e in (raw.get("elements") or []) if isinstance(e, dict) and e.get("file")]
    # Joern reports <empty>/<unknown> file names for synthetic nodes.
    elements = [e for e in elements if not str(e.get("file")).startswith("<")]
    if len(elements) < 2:
        return None
    groups = _group_by_method(elements)
    hops: List[FlowHop] = []
    n = len(groups)
    for i, group in enumerate(groups):
        if i == 0:
            role, label = "source", str(group[0].get("code") or "")[:120]
        elif i == n - 1:
            role, label = "sink", str(raw.get("sink_code") or group[-1].get("code") or "")[:120]
        else:
            role, label = "hop", f"{group[0].get('method') or ''}(...)"
        hop = _hop(group, role, label, src)
        if hop is None:
            return None
        hops.append(hop)
    if len(hops) == 1:
        # Source and sink in one method: still one hop, but flow_verify expects
        # the last hop to be the sink.
        hops[0].role = "sink"
        hops[0].label = str(raw.get("sink_code") or hops[0].label)[:120]
        # _hop anchored it at the source; a finding with no line of its own
        # falls back to the sink hop's line, which must be the sink call.
        sink_lines = [int(e.get("line") or -1) for e in elements if int(e.get("line") or -1) > 0]
        if sink_lines:
            hops[0].line = sink_lines[-1]
    files: List[str] = []
    for h in hops:
        if h.file not in files:
            files.append(h.file)
    taint_path = [
        {"file": _norm(e.get("file") or ""), "line": int(e.get("line") or -1),
         "method": e.get("method") or "", "code": str(e.get("code") or "")[:200]}
        for e in elements
    ]
    return Flow(
        hops=hops,
        entry_tier=ENTRY_TIER,
        sink_kind=str(raw.get("sink_kind") or "unknown"),
        authenticated=bool(set(raw.get("source_annotations") or []) & _AUTH_ANNOTATIONS),
        files=files,
        taint_path=taint_path,
        guards=_locations(raw.get("guards")),
        sanitizers=_locations(raw.get("sanitizers")),
    )


def _rank(flow: Flow) -> Tuple[int, int, int, int, int, int]:
    # Flows through a known sanitizer last (still verified if there's room),
    # then the high-volume Joern-only kinds. Within the rest: cross-file first
    # (what the deep scan can't see), then sink severity, then unauthenticated
    # entry points, then shorter paths (fewer places for the model to lose
    # the thread).
    return (
        1 if flow.sanitizers else 0,
        1 if flow.sink_kind in _LOW_VALUE_KINDS else 0,
        0 if len(flow.files) > 1 else 1,
        _SINK_SEVERITY.get(flow.sink_kind, 9),
        1 if flow.authenticated else 0,
        len(flow.taint_path),
    )


def flows_from_joern(
    raw_results: Iterable[Optional[Dict[str, Any]]],
    repo_root: Path,
    *,
    cap: int,
    deep_scanned_paths: Optional[Set[str]] = None,
) -> Tuple[List[Flow], int]:
    """Merge flows.sc results (one per CPG) into ranked Flows.

    Single-file flows are dropped when that file already went through the
    full-file LLM deep scan — the model saw the whole file there, so a second
    pass over the same code is spend without new coverage. Flows reaching the
    same sink collapse to the best-ranked one (collapse_flows_by_sink).

    Returns (flows[:cap], distinct sinks before the cap).
    """
    src = _SourceCache(repo_root)
    deep = {_norm(p) for p in (deep_scanned_paths or set())}
    seen: Set[Tuple] = set()
    flows: List[Flow] = []
    for result in raw_results:
        for raw in (result or {}).get("flows") or []:
            flow = flow_from_raw(raw, src)
            if flow is None:
                continue
            if len(flow.files) == 1 and flow.files[0] in deep:
                continue
            sig = (flow.hops[0].file, flow.hops[0].line, flow.hops[-1].file, flow.hops[-1].line, flow.sink_kind)
            if sig in seen:
                continue
            seen.add(sig)
            flows.append(flow)
    flows.sort(key=_rank)
    flows = collapse_flows_by_sink(flows)
    return flows[: max(0, cap)], len(flows)
