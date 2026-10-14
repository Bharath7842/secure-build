"""Symbol services for the hunt: definitions, callers, enclosing methods and
call-edge resolution — resolved by the strongest available analysis.

1. Joern taint paths (flows the CPG already proved, from `flow_candidates`),
   used to confirm a whole source->sink path.
2. The tree-sitter CallGraph (`state["call_graph"]["_graph"]`), whose edges
   come from receiver-type resolution, not name matching. If the scan didn't
   build one (inter-file-call-graph off), it is built once over the Java
   inventory on the first symbol query.
3. ripgrep, for navigation only. Every textual result is labelled
   `resolution="textual"`, and the validator never treats it as proof.
"""

from __future__ import annotations

import bisect
import re
import threading
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from pipeline.call_graph import CallGraph, JavaMethod, _is_framework_entry
from pipeline.hunt.evidence import RESOLUTION_GRAPH, RESOLUTION_JOERN, RESOLUTION_TEXTUAL
from pipeline.hunt.rg_runner import RgRunner

_IDENT_RE = re.compile(r"^[A-Za-z_$][\w$]*$")


@dataclass(frozen=True)
class SymbolHit:
    file: str
    line: int
    end_line: int
    name: str
    fqcn: str
    signature: str
    resolution: str
    kind: str = "method"  # method | type


@dataclass(frozen=True)
class CallerHit:
    file: str
    line: int  # the call site
    caller: str  # fqcn.method of the calling method ("" when textual)
    callee_file: str
    callee: str
    resolution: str


def parse_symbol(symbol: str) -> Tuple[Optional[str], Optional[str]]:
    """'OrderDao.find(' -> ('OrderDao', 'find'); 'OrderDao' -> ('OrderDao', None);
    'find' -> (None, 'find'). Anything that isn't an identifier -> (None, None)."""
    text = (symbol or "").strip().rstrip("(); ")
    parts = [p for p in re.split(r"\.|#|::", text) if p]
    if not parts or not all(_IDENT_RE.match(p) for p in parts):
        return None, None
    if len(parts) == 1:
        return (parts[0], None) if parts[0][:1].isupper() else (None, parts[0])
    owner, member = parts[-2], parts[-1]
    if member[:1].isupper():  # pkg.Type
        return member, None
    return owner, member


class SymbolService:
    def __init__(
        self,
        root: Path | str,
        runner: RgRunner,
        *,
        graph: Optional[CallGraph] = None,
        graph_builder: Optional[Callable[[], Optional[CallGraph]]] = None,
        joern_flows: Sequence[Dict[str, Any]] = (),
    ) -> None:
        self.root = Path(root)
        self.runner = runner
        self._graph = graph
        self._graph_builder = graph_builder if graph is None else None
        self._lock = threading.Lock()
        self._indexed = False
        self._methods_by_file: Dict[str, List[Tuple[int, int, str]]] = {}
        self._starts_by_file: Dict[str, List[int]] = {}
        self._incoming: Dict[str, List[Any]] = defaultdict(list)
        self._outgoing: Dict[str, List[Any]] = defaultdict(list)
        self._methods_by_name: Dict[str, List[str]] = defaultdict(list)
        self._sinks_by_file: Dict[str, List[Any]] = defaultdict(list)
        self.joern_paths: List[List[Dict[str, Any]]] = [
            list(f.get("taint_path") or []) for f in joern_flows
            if f.get("entry_tier") == "joern" and f.get("taint_path")
        ]

    # -- graph access ------------------------------------------------------

    @property
    def graph(self) -> Optional[CallGraph]:
        with self._lock:
            if self._graph is None and self._graph_builder is not None:
                builder, self._graph_builder = self._graph_builder, None
                try:
                    self._graph = builder()
                except Exception:  # noqa: BLE001 — fall back to textual navigation
                    self._graph = None
            if self._graph is not None and not self._indexed:
                self._index(self._graph)
            return self._graph

    def _index(self, graph: CallGraph) -> None:
        per_file: Dict[str, List[Tuple[int, int, str]]] = defaultdict(list)
        for key, m in graph.methods.items():
            per_file[m.file].append((m.start_line, m.end_line, key))
            self._methods_by_name[m.name].append(key)
        for file, spans in per_file.items():
            spans.sort()
            self._methods_by_file[file] = spans
            self._starts_by_file[file] = [s for s, _e, _k in spans]
        for edge in graph.edges:
            self._incoming[edge.callee_key].append(edge)
            self._outgoing[edge.caller_key].append(edge)
        for sink in graph.sinks:
            self._sinks_by_file[sink.file].append(sink)
        self._indexed = True

    def has_graph(self) -> bool:
        return self.graph is not None

    # -- lookups -----------------------------------------------------------

    def enclosing_method(self, file: str, line: int) -> Optional[JavaMethod]:
        graph = self.graph
        if graph is None:
            return None
        spans = self._methods_by_file.get(file) or []
        starts = self._starts_by_file.get(file) or []
        idx = bisect.bisect_right(starts, line) - 1
        # Innermost enclosing span: walk back over earlier-starting spans.
        best: Optional[Tuple[int, int, str]] = None
        while idx >= 0:
            start, end, key = spans[idx]
            if start <= line <= end and (best is None or start >= best[0]):
                best = (start, end, key)
            idx -= 1
        return graph.methods.get(best[2]) if best else None

    def definitions(self, symbol: str, *, limit: int = 15) -> List[SymbolHit]:
        owner, member = parse_symbol(symbol)
        if owner is None and member is None:
            return []
        graph = self.graph
        hits: List[SymbolHit] = []
        if graph is not None:
            if member is None and owner:
                for fqcn in graph.types_by_simple.get(owner, [])[:limit]:
                    jtype = graph.types.get(fqcn)
                    if jtype is None:
                        continue
                    line = self._type_decl_line(jtype.file, owner)
                    hits.append(SymbolHit(
                        file=jtype.file, line=line, end_line=line, name=owner, fqcn=fqcn,
                        signature=f"{jtype.kind} {owner}", resolution=RESOLUTION_GRAPH, kind="type",
                    ))
            elif member:
                for key in self._methods_by_name.get(member, []):
                    m = graph.methods[key]
                    if owner and m.fqcn.rsplit(".", 1)[-1] != owner:
                        continue
                    hits.append(SymbolHit(
                        file=m.file, line=m.start_line, end_line=m.end_line, name=m.name,
                        fqcn=m.fqcn, signature=_signature(m), resolution=RESOLUTION_GRAPH,
                    ))
                    if len(hits) >= limit:
                        break
        if hits:
            return hits
        return self._textual_definitions(owner, member, limit=limit)

    def callers(self, method: str, class_name: Optional[str] = None, *, limit: int = 25) -> List[CallerHit]:
        owner, member = parse_symbol(f"{class_name}.{method}" if class_name else method)
        member = member or (owner if owner and not class_name else None)
        if not member:
            return []
        graph = self.graph
        hits: List[CallerHit] = []
        if graph is not None:
            for key in self._methods_by_name.get(member, []):
                callee = graph.methods[key]
                if owner and callee.fqcn.rsplit(".", 1)[-1] != owner:
                    continue
                for edge in self._incoming.get(key, []):
                    caller = graph.methods.get(edge.caller_key)
                    if caller is None:
                        continue
                    hits.append(CallerHit(
                        file=caller.file, line=edge.call_line, caller=f"{caller.fqcn}.{caller.name}",
                        callee_file=callee.file, callee=f"{callee.fqcn}.{callee.name}",
                        resolution=RESOLUTION_GRAPH,
                    ))
                    if len(hits) >= limit:
                        return hits
        if hits:
            return hits
        return self._textual_callers(member, limit=limit)

    def edge_resolution(
        self, *, caller_file: str, call_line: int, callee_file: str, callee_name: Optional[str] = None,
        slack: int = 2,
    ) -> Optional[str]:
        """How strongly a call at caller_file:~call_line into a method in
        callee_file is established: 'graph' if the CallGraph has that edge,
        else None (a textual match is not an edge)."""
        graph = self.graph
        if graph is None:
            return None
        caller = self.enclosing_method(caller_file, call_line)
        if caller is None:
            return None
        for edge in self._outgoing.get(caller.key, []):
            if abs(edge.call_line - call_line) > slack:
                continue
            callee = graph.methods.get(edge.callee_key)
            if callee is None or callee.file != callee_file:
                continue
            if callee_name and callee.name != callee_name:
                continue
            return RESOLUTION_GRAPH
        return None

    def graph_sink_kind(self, file: str, line: int, *, slack: int = 1) -> Optional[str]:
        """Sink kind the CallGraph resolved (by receiver type) at file:line."""
        if self.graph is None:
            return None
        for sink in self._sinks_by_file.get(file, []):
            if abs(sink.line - line) <= slack:
                return sink.kind
        return None

    def is_framework_entry_at(self, file: str, line: int) -> bool:
        method = self.enclosing_method(file, line)
        return bool(method and _is_framework_entry(method))

    def joern_covers(
        self, *, source_file: str, source_line: int, sink_file: str, sink_line: int, slack: int = 3,
    ) -> bool:
        """True when a Joern taint path starts at the source and ends at the
        sink (each within `slack` lines)."""
        for path in self.joern_paths:
            first, last = path[0], path[-1]
            if (
                first.get("file") == source_file and abs(int(first.get("line") or 0) - source_line) <= slack
                and last.get("file") == sink_file and abs(int(last.get("line") or 0) - sink_line) <= slack
            ):
                return True
        return False

    # -- textual fallbacks -------------------------------------------------

    def _type_decl_line(self, file: str, simple: str) -> int:
        try:
            lines = (self.root / file).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return 1
        decl = re.compile(rf"\b(?:class|interface|enum|record)\s+{re.escape(simple)}\b")
        for i, text in enumerate(lines, start=1):
            if decl.search(text):
                return i
        return 1

    def _textual_definitions(self, owner: Optional[str], member: Optional[str], *, limit: int) -> List[SymbolHit]:
        if member:
            pattern = rf"\b{re.escape(member)}\s*\([^;{{]*\)\s*(?:throws\s[^{{;]*)?\{{"
        else:
            pattern = rf"\b(?:class|interface|enum|record)\s+{re.escape(owner or '')}\b"
        result = self.runner.search(pattern, trusted=True, max_count_per_file=5)
        hits: List[SymbolHit] = []
        for m in result.matches[:limit]:
            if owner and member and Path(m.file).stem != owner:
                continue
            hits.append(SymbolHit(
                file=m.file, line=m.line, end_line=m.line, name=member or owner or "",
                fqcn="", signature=m.text.strip()[:200], resolution=RESOLUTION_TEXTUAL,
                kind="method" if member else "type",
            ))
        return hits

    def _textual_callers(self, member: str, *, limit: int) -> List[CallerHit]:
        result = self.runner.search(rf"(?:\.|\b){re.escape(member)}\s*\(", trusted=True, max_count_per_file=10)
        definition = re.compile(
            rf"(?:public|private|protected|static|void|[\w<>\[\]]+)\s+{re.escape(member)}\s*\([^)]*\)\s*(?:throws[^{{]*)?\{{?\s*$"
        )
        hits: List[CallerHit] = []
        for m in result.matches:
            if definition.search(m.text.strip()):
                continue
            hits.append(CallerHit(
                file=m.file, line=m.line, caller="", callee_file="", callee=member,
                resolution=RESOLUTION_TEXTUAL,
            ))
            if len(hits) >= limit:
                break
        return hits


def _signature(method: JavaMethod) -> str:
    """The declaration line — the method node's text starts with any
    annotations, so the first line is often `@GetMapping(...)`."""
    decl = re.compile(rf"\b{re.escape(method.name)}\s*\(")
    for text in (method.body or "").splitlines():
        if decl.search(text):
            return text.strip()[:200]
    return f"{method.name}(...)"


def build_lazy_graph_builder(root: Path, java_paths: Sequence[str]) -> Callable[[], Optional[CallGraph]]:
    """Builder for scans that didn't build the CallGraph themselves."""
    def _build() -> Optional[CallGraph]:
        if not java_paths:
            return None
        from pipeline.call_graph import build_call_graph

        return build_call_graph(Path(root), list(java_paths))
    return _build


__all__ = [
    "CallerHit", "SymbolHit", "SymbolService", "build_lazy_graph_builder", "parse_symbol",
    "RESOLUTION_GRAPH", "RESOLUTION_JOERN", "RESOLUTION_TEXTUAL",
]
