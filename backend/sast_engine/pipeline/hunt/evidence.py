"""What an investigator actually observed — the only evidence a finding may cite.

Every tool call that shows code to the model records the exact file/line
span it showed (plus a hash of the unredacted text) here, and every call-
edge lookup records how it was resolved. The validator then accepts a
finding's source, sink and hops only if they fall inside observed spans, and
grades the finding by the weakest edge resolution on its path — so a model
cannot cite code it never saw, and a regex-guessed hop can never be
presented as proof.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

RESOLUTION_JOERN = "joern"
RESOLUTION_GRAPH = "graph"
RESOLUTION_TEXTUAL = "textual"
# Two points in one method body, with every line between them shown to the
# investigator: the data flow was observed directly, not inferred.
RESOLUTION_READ = "read"
_RESOLUTION_STRENGTH = {RESOLUTION_JOERN: 3, RESOLUTION_GRAPH: 2, RESOLUTION_READ: 2, RESOLUTION_TEXTUAL: 1}


def resolution_strength(resolution: Optional[str]) -> int:
    return _RESOLUTION_STRENGTH.get(resolution or "", 0)


def content_hash(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="replace")).hexdigest()[:16]


@dataclass(frozen=True)
class Observation:
    tool: str
    file: str
    start: int
    end: int
    digest: str = ""


@dataclass(frozen=True)
class EdgeObservation:
    """A call from `caller_file:call_line` into `callee_name` (defined in
    `callee_file`, when known), and how that link was established."""
    caller_file: str
    call_line: int
    callee_name: str
    callee_file: str
    resolution: str


@dataclass
class EvidenceLedger:
    observations: List[Observation] = field(default_factory=list)
    edges: List[EdgeObservation] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record_span(self, tool: str, file: str, start: int, end: int, text: str = "") -> None:
        if not file or start <= 0:
            return
        with self._lock:
            self.observations.append(
                Observation(tool=tool, file=file, start=start, end=max(start, end), digest=content_hash(text))
            )

    def record_line(self, tool: str, file: str, line: int, text: str = "") -> None:
        self.record_span(tool, file, line, line, text)

    def record_edge(
        self, *, caller_file: str, call_line: int, callee_name: str, callee_file: str, resolution: str,
    ) -> None:
        with self._lock:
            self.edges.append(EdgeObservation(
                caller_file=caller_file, call_line=int(call_line or 0), callee_name=callee_name,
                callee_file=callee_file, resolution=resolution,
            ))

    def covers(self, file: str, line: int, *, slack: int = 0) -> bool:
        """Was `file:line` shown to the model by some tool call?"""
        with self._lock:
            return any(
                o.file == file and o.start - slack <= line <= o.end + slack
                for o in self.observations
            )

    def files_seen(self) -> List[str]:
        with self._lock:
            return sorted({o.file for o in self.observations})

    def best_edge(
        self, *, caller_file: str, callee_file: str, callee_name: Optional[str] = None,
        call_line: Optional[int] = None, slack: int = 3,
    ) -> Optional[EdgeObservation]:
        """Strongest recorded edge between two files (optionally a named
        callee / near a call line)."""
        with self._lock:
            candidates = [
                e for e in self.edges
                if e.caller_file == caller_file and e.callee_file == callee_file
                and (callee_name is None or e.callee_name == callee_name)
                and (call_line is None or abs(e.call_line - call_line) <= slack)
            ]
        if not candidates:
            return None
        return max(candidates, key=lambda e: resolution_strength(e.resolution))

    def summary(self) -> Dict[str, object]:
        with self._lock:
            by_res: Dict[str, int] = {}
            for e in self.edges:
                by_res[e.resolution] = by_res.get(e.resolution, 0) + 1
            return {
                "observations": len(self.observations),
                "files": len({o.file for o in self.observations}),
                "edges": by_res,
            }


def spans_overlap(a: Tuple[int, int], b: Tuple[int, int]) -> bool:
    return a[0] <= b[1] and b[0] <= a[1]
