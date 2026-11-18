"""§9 dependency graph: edges, reverse lookup, paths, cycles and orphans."""

from collections import deque

from ..graph.state import SBOMState

MAX_EXAMPLES = 50


def dependency_graph_node(state: SBOMState) -> dict:
    components = state.get("components", []) or []
    raw_edges = state.get("dependency_edges") or state.get("edges") or []
    warnings = list(state.get("warnings", []))

    ref_of: dict[str, str] = {}
    nodes_by_ref: dict[str, dict] = {}

    for comp in components:
        if not isinstance(comp, dict):
            continue
        purl = comp.get("purl", "")
        bom_ref = comp.get("bom-ref") or purl
        canonical = bom_ref or purl
        if not canonical:
            continue
        ref_of[canonical] = canonical
        if purl:
            ref_of[purl] = canonical
        if bom_ref:
            ref_of[bom_ref] = canonical
        nodes_by_ref.setdefault(canonical, {
            "ref": canonical,
            "name": comp.get("name", ""),
            "version": comp.get("version", ""),
            "purl": purl,
            "bom-ref": bom_ref,
            "ecosystem": comp.get("ecosystem", ""),
            "scope": comp.get("scope", ""),
            "direct": bool(comp.get("direct")),
            "source_file": comp.get("source_file", ""),
            "kind": "component",
        })

    def canon(ref: str) -> str:
        return ref_of.get(ref, ref)

    adjacency: dict[str, list[str]] = {}
    self_loops: list[str] = []

    def add_edge(parent: str, child: str) -> None:
        if not parent or not child:
            return
        if parent == child:
            if parent not in self_loops:
                self_loops.append(parent)
            return
        bucket = adjacency.setdefault(parent, [])
        if child not in bucket:
            bucket.append(child)

    for edge in raw_edges:
        if not isinstance(edge, dict):
            continue
        parent = canon(edge.get("ref", ""))
        for child in (edge.get("dependsOn") or []):
            add_edge(parent, canon(child))

    for comp in components:
        if not isinstance(comp, dict):
            continue
        parent = canon(comp.get("bom-ref") or comp.get("purl", ""))
        for child in (comp.get("depends_on") or []):
            add_edge(parent, canon(child))

    peer_pairs: set[tuple[str, str]] = set()
    for comp in components:
        if not isinstance(comp, dict):
            continue
        peers = comp.get("peer_depends_on")
        if not isinstance(peers, list) or not peers:
            continue
        parent = canon(comp.get("bom-ref") or comp.get("purl", ""))
        if not parent:
            continue
        for child in peers:
            child_ref = canon(child)
            if child_ref and child_ref != parent:
                peer_pairs.add((parent, child_ref))

    reverse: dict[str, list[str]] = {}
    for parent, children in adjacency.items():
        for child in children:
            reverse.setdefault(child, []).append(parent)

    # §4/§9: a declared direct dependency of the project has no *inter-package*
    # parent. Attach those to the real project root so roots, paths and orphans
    # describe the repository rather than a flat manifest.
    metadata = state.get("project_metadata") or {}
    project_ref = _project_ref(metadata)
    if project_ref:
        adopted = 0
        for ref, node in nodes_by_ref.items():
            if node["kind"] == "component" and node.get("direct") and ref not in reverse:
                add_edge(project_ref, ref)
                adopted += 1
        if adopted:
            reverse = {}
            for parent, children in adjacency.items():
                for child in children:
                    reverse.setdefault(child, []).append(parent)

    all_refs: set[str] = set(nodes_by_ref) | set(adjacency) | set(reverse)
    for children in adjacency.values():
        all_refs.update(children)

    # Any reference that only ever appears as a parent is the scanned project root.
    project_roots = sorted(
        ref for ref in adjacency
        if ref not in reverse and ref not in nodes_by_ref
    )
    roots = sorted(ref for ref in all_refs if ref not in reverse)

    depths, paths = _breadth_first(roots, adjacency)
    cycle_adjacency = {
        parent: [child for child in children if (parent, child) not in peer_pairs]
        for parent, children in adjacency.items()
    }
    cycle_adjacency = {
        parent: children for parent, children in cycle_adjacency.items() if children
    }
    cycles = _find_cycles(all_refs, cycle_adjacency)
    if cycles:
        warnings.append({
            "node": "dependency_graph",
            "warning": f"{len(cycles)} dependency cycle(s) detected",
            "cycles": [c[:MAX_EXAMPLES] for c in cycles[:10]],
        })

    orphans = sorted(
        ref for ref in nodes_by_ref
        if ref not in adjacency and ref not in reverse
    )
    if orphans:
        warnings.append({
            "node": "dependency_graph",
            "warning": f"{len(orphans)} component(s) are not referenced by any dependency edge",
            "orphans": orphans[:MAX_EXAMPLES],
        })

    for ref, node in nodes_by_ref.items():
        node["depth"] = depths.get(ref)
        node["parents"] = sorted(reverse.get(ref, []))
        node["children"] = sorted(adjacency.get(ref, []))
        node["path"] = paths.get(ref, [])

    for ref in all_refs:
        if ref in nodes_by_ref:
            continue
        name, version = _parse_ref_identity(ref)
        nodes_by_ref[ref] = {
            "ref": ref,
            "name": name,
            "version": version,
            "purl": ref if ref.startswith("pkg:") else "",
            "bom-ref": ref,
            "ecosystem": "",
            "scope": "",
            "direct": False,
            "source_file": "",
            "kind": "project" if ref in project_roots else "reference",
            "depth": depths.get(ref),
            "parents": sorted(reverse.get(ref, [])),
            "children": sorted(adjacency.get(ref, [])),
            "path": paths.get(ref, []),
        }

    direct = sorted(r for r, n in nodes_by_ref.items() if n["kind"] == "component" and n["direct"])
    transitive = sorted(
        r for r, n in nodes_by_ref.items() if n["kind"] == "component" and not n["direct"]
    )

    graph = {
        "project_ref": project_ref,
        "nodes": [nodes_by_ref[r] for r in sorted(nodes_by_ref)],
        "edges": [
            {"ref": parent, "dependsOn": sorted(children)}
            for parent, children in sorted(adjacency.items())
        ],
        "adjacency": {r: sorted(c) for r, c in sorted(adjacency.items())},
        "reverse": {r: sorted(p) for r, p in sorted(reverse.items())},
        "roots": roots,
        "project_roots": project_roots,
        "direct": direct,
        "transitive": transitive,
        "depths": {r: depths[r] for r in sorted(depths)},
        "paths": {r: paths[r] for r in sorted(paths)},
        "cycles": cycles,
        "orphans": orphans,
        "stats": {
            "node_count": len(nodes_by_ref),
            "component_count": len(nodes_by_ref) - len(project_roots) - len(
                [r for r, n in nodes_by_ref.items() if n["kind"] == "reference"]
            ),
            "edge_count": sum(len(c) for c in adjacency.values()),
            "root_count": len(roots),
            "direct_count": len(direct),
            "transitive_count": len(transitive),
            "orphan_count": len(orphans),
            "cycle_count": len(cycles),
            "self_loop_count": len(self_loops),
            "max_depth": max(depths.values(), default=0),
        },
    }

    return {"dependency_graph": graph, "edges": graph["edges"], "warnings": warnings}


def _project_ref(metadata: dict) -> str:
    """Canonical purl for the scanned project itself (§4). Empty when undeterminable."""
    from urllib.parse import quote

    name = (metadata or {}).get("project_name", "")
    if not name or name in ("unknown", "scanned-project"):
        return ""
    version = (metadata or {}).get("project_version", "")
    base = f"pkg:generic/{quote(name, safe='')}"
    if version and version != "unknown":
        return f"{base}@{version}"
    return base


def _parse_ref_identity(ref: str) -> tuple[str, str]:
    """Best-effort `name`/`version` for project and reference nodes (§9)."""
    if not ref.startswith("pkg:"):
        return ref, ""
    rest = ref[4:].split("?", 1)[0]
    _, _, path = rest.partition("/")
    if not path:
        return rest, ""
    if "@" in path:
        name, _, version = path.rpartition("@")
    else:
        name, version = path, ""
    return name.rsplit("/", 1)[-1] or name, version


def _breadth_first(roots: list[str], adjacency: dict[str, list[str]]) -> tuple[dict, dict]:
    """Shortest root-to-component depth and the path realizing it (§9)."""
    depths: dict[str, int] = {}
    paths: dict[str, list[str]] = {}
    queue: deque[str] = deque()

    for root in roots:
        depths[root] = 0
        paths[root] = [root]
        queue.append(root)

    while queue:
        current = queue.popleft()
        for child in adjacency.get(current, []):
            if child in depths:
                continue
            depths[child] = depths[current] + 1
            paths[child] = paths[current] + [child]
            queue.append(child)

    return depths, paths


def _find_cycles(all_refs: set[str], adjacency: dict[str, list[str]]) -> list[list[str]]:
    """Iterative DFS cycle detection; each cycle is returned once (§9)."""
    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = {}
    cycles: list[list[str]] = []
    seen: set[frozenset[str]] = set()

    for start in sorted(all_refs):
        if color.get(start, WHITE) != WHITE:
            continue
        stack: list[tuple[str, object]] = [(start, iter(adjacency.get(start, [])))]
        color[start] = GRAY
        path = [start]
        while stack:
            node, children = stack[-1]
            descended = False
            for child in children:
                state = color.get(child, WHITE)
                if state == GRAY:
                    cycle = path[path.index(child):] + [child] if child in path else [child, child]
                    key = frozenset(cycle)
                    if key not in seen:
                        seen.add(key)
                        cycles.append(cycle)
                elif state == WHITE:
                    color[child] = GRAY
                    path.append(child)
                    stack.append((child, iter(adjacency.get(child, []))))
                    descended = True
                    break
            if not descended:
                color[node] = BLACK
                stack.pop()
                path.pop()

    return cycles
