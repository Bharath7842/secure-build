"""call_graph_common.py — the small adapter seam between derive_rules.py and
the per-language call-graph builders (Java's `CallGraph`, Python's
`PyCallGraph`).

`derive_rules.py` used to import `CallGraph` directly and reach into its
Java-shaped internals (`graph.sinks`, `graph.methods[key].fqcn`, ...). Adding
a second language meant either duplicating derive_rules.py per language or
introducing this seam once: a tiny, language-agnostic view each graph type
implements, so derive_rules.py never needs to know which language built the
graph it was handed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Protocol, Sequence


@dataclass
class CallerInfo:
    name: str
    display: str
    file: str
    is_constructor: bool


class GraphAdapter(Protocol):
    language: str

    def sink_hits(self) -> Sequence:
        ...

    def caller_info(self, caller_key: str) -> Optional[CallerInfo]:
        ...

    def is_test_path(self, path: str) -> bool:
        ...

    def type_names(self, limit: int) -> List[str]:
        ...
