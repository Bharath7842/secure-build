"""Resource relationship graph used by advanced policy checks."""

from dataclasses import dataclass, field
from typing import Any, Iterable


@dataclass
class ResourceNode:
    id: str
    type: str
    provider: str
    name: str
    file: str
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class ResourceEdge:
    source: str
    target: str
    relationship: str
    metadata: dict[str, Any] = field(default_factory=dict)


class ResourceGraph:
    """Directed graph of IaC resources.

    Graph analysis is optional. Queries that do not need relationships
    should inspect NormalizedDocument resources directly.
    """

    def __init__(self) -> None:
        self.nodes: dict[str, ResourceNode] = {}
        self.edges: list[ResourceEdge] = []
        self._adjacency: dict[str, list[ResourceEdge]] = {}

    def add_node(self, node: ResourceNode) -> None:
        self.nodes[node.id] = node
        self._adjacency.setdefault(node.id, [])

    def add_edge(self, edge: ResourceEdge) -> None:
        if edge.source not in self.nodes or edge.target not in self.nodes:
            return
        self.edges.append(edge)
        self._adjacency.setdefault(edge.source, []).append(edge)

    def neighbors(self, node_id: str, relationship: str | None = None) -> list[ResourceNode]:
        result = []
        for edge in self._adjacency.get(node_id, []):
            if relationship and edge.relationship != relationship:
                continue
            node = self.nodes.get(edge.target)
            if node:
                result.append(node)
        return result

    def nodes_by_type(self, resource_type: str) -> list[ResourceNode]:
        return [n for n in self.nodes.values() if n.type == resource_type]

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [
                {
                    "id": n.id,
                    "type": n.type,
                    "provider": n.provider,
                    "name": n.name,
                    "file": n.file,
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "relationship": e.relationship,
                }
                for e in self.edges
            ],
        }

    @staticmethod
    def from_nodes(nodes: Iterable[ResourceNode]) -> "ResourceGraph":
        graph = ResourceGraph()
        for node in nodes:
            graph.add_node(node)
        return graph
