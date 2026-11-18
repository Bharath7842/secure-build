"""Helpers for classifying direct vs transitive dependencies."""


def collect_child_refs(edges: list[dict] | None, components: list[dict] | None = None) -> set[str]:
    children: set[str] = set()
    for edge in edges or []:
        for child in edge.get("dependsOn") or []:
            if child:
                children.add(child)
    for comp in components or []:
        for child in comp.get("depends_on") or []:
            if child:
                children.add(child)
    return children


def derive_direct_refs(
    components: list[dict],
    *,
    edges: list[dict] | None = None,
    preferred_direct_refs: set[str] | None = None,
) -> set[str]:
    """Return refs/purls that should be marked direct.

    Preference order:
    1. preferred_direct_refs that actually match a component (e.g. root dependsOn)
    2. components that never appear as someone else's dependency (top-level)
    """
    if not components:
        return set()

    comp_refs: set[str] = set()
    for comp in components:
        bom_ref = comp.get("bom-ref") or ""
        purl = comp.get("purl") or ""
        if bom_ref:
            comp_refs.add(bom_ref)
        if purl:
            comp_refs.add(purl)

    if preferred_direct_refs:
        matched = {ref for ref in preferred_direct_refs if ref in comp_refs}
        if matched:
            return matched

    children = collect_child_refs(edges, components)
    return {
        ref
        for ref in comp_refs
        if ref not in children
    }


def apply_direct_flags(
    components: list[dict],
    *,
    edges: list[dict] | None = None,
    preferred_direct_refs: set[str] | None = None,
    force: bool = False,
) -> list[dict]:
    """Set boolean `direct` on components. If force=False, only when all are indirect."""
    if not components:
        return components

    has_any_direct = any(
        (str(c.get("direct")).strip().lower() in ("true", "1", "yes") if isinstance(c.get("direct"), str) else bool(c.get("direct")))
        for c in components
        if isinstance(c, dict)
    )
    if has_any_direct and not force:
        for comp in components:
            if not isinstance(comp, dict):
                continue
            value = comp.get("direct")
            if isinstance(value, str):
                comp["direct"] = value.strip().lower() in ("true", "1", "yes")
            else:
                comp["direct"] = bool(value)
        return components

    direct_refs = derive_direct_refs(
        components,
        edges=edges,
        preferred_direct_refs=preferred_direct_refs,
    )
    if not direct_refs:
        return components

    for comp in components:
        if not isinstance(comp, dict):
            continue
        bom_ref = comp.get("bom-ref") or ""
        purl = comp.get("purl") or ""
        comp["direct"] = bom_ref in direct_refs or purl in direct_refs
    return components
