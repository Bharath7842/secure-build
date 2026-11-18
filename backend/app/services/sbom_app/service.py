"""SBOM generation service entry point.

Chains the five SBOM nodes sequentially over SBOMState and returns
the final state containing components, dependency_graph, licenses,
and sboms.
"""

from __future__ import annotations

import logging
from pathlib import Path

from .graph.state import SBOMState
from .nodes.ecosystem import ecosystem_node
from .nodes.dependency import dependency_node
from .nodes.normalize import normalize_node
from .nodes.dependency_graph import dependency_graph_node
from .nodes.license import license_node

logger = logging.getLogger("sbom.service")


def run_sbom(repository_path: str) -> dict:
    """Run the full SBOM pipeline on *repository_path* (includes license lookup).

    Returns the merged SBOMState dict on success, or a dict with
    ``{"error": <message>}`` when an unhandled exception occurs.
    """
    try:
        state: SBOMState = {
            "repository_path": repository_path,
            "scan_id": "",
            "source_type": "local",
            "warnings": [],
            "errors": [],
        }

        # Node 1: detect ecosystems and manifest/lockfile paths
        state.update(ecosystem_node(state))

        # Node 2: collect raw dependency sightings
        state.update(dependency_node(state))

        # Node 3: normalize components (dedupe, purl generation, etc.)
        state.update(normalize_node(state))

        # Node 4: build dependency graph (edges, cycles, orphans)
        state.update(dependency_graph_node(state))

        # Node 5: resolve licenses (ClearlyDefined / deps.dev / text)
        state.update(license_node(state))

        return dict(state)
    except Exception as exc:
        logger.exception("SBOM pipeline failed for %s: %s", repository_path, exc)
        return {"error": str(exc), "components": [], "licenses": [], "dependency_graph": {}}


def run_sbom_fast(repository_path: str) -> dict:
    """Run the SBOM pipeline without the slow ClearlyDefined license lookup.

    Runs nodes 1-4 only: ecosystem detection, dependency collection, component
    normalisation and dependency graph.  License enrichment (node 5) is skipped
    because it makes external network calls that can take minutes per repository —
    for in-scan security analysis (SCA/VEX) we only need the component inventory
    and package purls, not full license metadata.

    Returns the merged SBOMState dict on success, or ``{"error": ...}`` on failure.
    """
    try:
        state: SBOMState = {
            "repository_path": repository_path,
            "scan_id": "",
            "source_type": "local",
            "warnings": [],
            "errors": [],
        }

        state.update(ecosystem_node(state))
        state.update(dependency_node(state))
        state.update(normalize_node(state))
        state.update(dependency_graph_node(state))

        return dict(state)
    except Exception as exc:
        logger.exception("SBOM fast pipeline failed for %s: %s", repository_path, exc)
        return {"error": str(exc), "components": [], "licenses": [], "dependency_graph": {}}
