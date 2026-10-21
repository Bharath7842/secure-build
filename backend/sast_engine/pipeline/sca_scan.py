"""sca_scan.py — deterministic Software Composition Analysis (SCA) pipeline.

MVP scope: walks the repo for dependency manifests already recognized by
`manifest_parsers.py`, batch-queries OSV.dev for known vulnerabilities
against each declared dependency, and turns hits into `Finding`-shaped
dicts (`kind="sca"`). Pure Python (stdlib + `requests`) — no LangGraph, no
LLM, no boto3 — so it never needs the dynamic `agent_bridge` loader the
SAST engine requires, and the mock-engine test suite never touches it at
all unless a test explicitly imports it.

Explicitly deferred (see the SCA plan): cdxgen-based SBOM generation, NVD/
deps.dev enrichment, Maven `dependency:tree` compatibility checking,
lockfile/transitive dependency resolution, LLM-generated developer
comments. All of those can layer on top of this module later without
touching its public functions.
"""

from __future__ import annotations

import math
import os
import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests

from . import manifest_parsers

OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
OSV_BATCH_SIZE = 1000
OSV_BATCH_TIMEOUT = 60
OSV_DETAIL_TIMEOUT = 15
# Per-dependency cap on how many individual OSV detail (GET) calls we make —
# mirrors the reference prototype's same cap, keeps a dependency with a huge
# advisory history from dominating scan time.
MAX_VULNS_PER_DEPENDENCY = 20

# Same directory-walk guard spirit as sast_scan_agent.DEFAULT_SKIP_DIRS, kept
# as a small independent copy here rather than importing that module (which
# pulls in langgraph/boto3 at import time — exactly what this module exists
# to avoid needing).
_SKIP_DIRS_LOWER = {
    ".git", ".svn", ".hg",
    "node_modules", "bower_components", "vendor",
    "target", "build", "dist", "out", "bin", "obj",
    "__pycache__", ".mypy_cache", ".pytest_cache",
    ".venv", "venv", "env",
    ".idea", ".vscode", ".vs",
    ".gradle", ".mvn", ".angular", ".next", "coverage",
}

# Same bound dependency_scan.py uses for its own manifest walk.
_MAX_MANIFESTS = 300

# manifest_parsers.py's lowercase ecosystem key -> OSV.dev's ecosystem name.
_OSV_ECOSYSTEM_MAP = {
    "maven": "Maven",
    "npm": "npm",
    "pypi": "PyPI",
    "go": "Go",
    "rubygems": "RubyGems",
    "packagist": "Packagist",
    "nuget": "NuGet",
    "cratesio": "crates.io",
}

_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
_SEVERITY_RANK = {level: idx for idx, level in enumerate(_SEVERITY_ORDER)}


# ===========================================================================
# Directory walk + manifest collection
# ===========================================================================


def walk_repo_files(repo_root: Path) -> Dict[str, Any]:
    """Minimal directory walk producing the ``{"files": [...]}`` shape
    `manifest_parsers`/this module's own helpers expect — a stripped-down
    sibling of `sast_scan_agent.node_scan_directory`'s walk, without the
    tracer/AST/categorization machinery SCA doesn't need."""
    files: List[Dict[str, Any]] = []
    for current_root, dirnames, filenames in os.walk(repo_root):
        pruned = [d for d in dirnames if d.lower() in _SKIP_DIRS_LOWER or d.startswith(".")]
        for d in pruned:
            dirnames.remove(d)
        rel_dir = os.path.relpath(current_root, repo_root)
        rel_dir = "" if rel_dir == "." else rel_dir.replace(os.sep, "/")
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            rel_path = f"{rel_dir}/{fname}" if rel_dir else fname
            files.append({"path": rel_path, "name": fname, "ext": ext})
    return {"files": files}


def _find_manifest_files(scan: Dict[str, Any]) -> List[Dict[str, Any]]:
    names = set(manifest_parsers.PARSERS_BY_FILENAME)
    exts = set(manifest_parsers.PARSERS_BY_EXT)
    return [f for f in scan["files"] if f["name"] in names or f["ext"] in exts]


def _read_text(repo_root: Path, rel_path: str) -> Optional[str]:
    try:
        return (repo_root / rel_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def collect_dependencies(repo_root: Path) -> List[Dict[str, Any]]:
    """Walks the repo and parses every recognized manifest, returning a flat,
    deduped list of ``{"ecosystem", "name", "version", "scope", "source_file"}``.

    Deliberately a *sibling* of `dependency_scan.analyze_dependencies`, not a
    caller of it — that function's final `declared_dependencies` output
    drops `ecosystem` (fine for its own stack-detection use case, since rule
    `requires_dependency` conditions match on name+version only), which SCA
    needs in order to build correct OSV.dev queries.
    """
    repo_root = Path(repo_root)
    scan = walk_repo_files(repo_root)
    manifest_files = _find_manifest_files(scan)[:_MAX_MANIFESTS]

    # Pre-read pom.xml <properties> across the whole repo so a child module's
    # ${property} placeholders can resolve against a parent pom found
    # elsewhere in the walk (best-effort, mirrors dependency_scan.py).
    merged_pom_properties: Dict[str, str] = {}
    for f in manifest_files:
        if f["name"] != "pom.xml":
            continue
        text = _read_text(repo_root, f["path"])
        if text:
            merged_pom_properties.update(manifest_parsers.extract_pom_properties(text))

    deps: List[Dict[str, Any]] = []
    seen: set = set()
    for f in manifest_files:
        text = _read_text(repo_root, f["path"])
        if text is None:
            continue
        if f["name"] == "pom.xml":
            parsed = manifest_parsers.parse_pom_xml(text, merged_pom_properties)
        else:
            parsed = manifest_parsers.parse_manifest(f["name"], f["ext"], text)
        for dep in parsed:
            key = (dep["ecosystem"], dep["name"], dep.get("version"))
            if key in seen:
                continue
            seen.add(key)
            deps.append({**dep, "source_file": f["path"]})
    return deps


# ===========================================================================
# OSV.dev lookup
# ===========================================================================


def _clean_version(version: Optional[str]) -> Optional[str]:
    """Best-effort strip of range/prefix operators (``^1.2.3``, ``>=1.0``,
    ``~1.2``) down to a bare version OSV's exact-version query can match.
    Leaves an unparseable string as-is rather than dropping it."""
    if not version:
        return None
    v = version.strip()
    v = re.sub(r"^[\^~=<>! ]+", "", v)
    v = v.split(",")[0].strip()
    return v or None


def build_osv_query(dependency: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    osv_ecosystem = _OSV_ECOSYSTEM_MAP.get(dependency.get("ecosystem"))
    version = _clean_version(dependency.get("version"))
    if not osv_ecosystem or not dependency.get("name") or not version:
        return None
    return {
        "version": version,
        "package": {"name": dependency["name"], "ecosystem": osv_ecosystem},
    }


def query_osv_batch(dependencies: List[Dict[str, Any]]) -> Dict[int, List[Dict[str, Any]]]:
    """POSTs ``api.osv.dev/v1/querybatch`` in batches of `OSV_BATCH_SIZE`.

    Returns ``{original_index: [vuln_stub, ...]}`` for every dependency that
    had at least one hit. No API key required. Network/HTTP failures on a
    batch are logged-and-skipped (best-effort — a partial SCA result is
    still strictly more useful than none)."""
    results: Dict[int, List[Dict[str, Any]]] = {}
    queryable = [(i, build_osv_query(dep)) for i, dep in enumerate(dependencies)]
    queryable = [(i, q) for i, q in queryable if q is not None]
    for batch_start in range(0, len(queryable), OSV_BATCH_SIZE):
        batch = queryable[batch_start : batch_start + OSV_BATCH_SIZE]
        try:
            resp = requests.post(
                OSV_QUERY_BATCH_URL,
                json={"queries": [q for _, q in batch]},
                timeout=OSV_BATCH_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
        except (requests.RequestException, ValueError):
            continue
        for (orig_index, _query), result in zip(batch, data.get("results", [])):
            vulns = result.get("vulns") or []
            if vulns:
                results[orig_index] = vulns
    return results


def get_full_osv_vulnerability(vuln_id: str) -> Optional[Dict[str, Any]]:
    """GETs full advisory detail for one OSV vuln id (the batch endpoint only
    returns id/modified stubs). Returns None on 404 or any request failure."""
    try:
        resp = requests.get(OSV_VULN_URL.format(id=vuln_id), timeout=OSV_DETAIL_TIMEOUT)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()
    except (requests.RequestException, ValueError):
        return None


# ===========================================================================
# Severity / CVE / fixed-version extraction
# ===========================================================================


def extract_cve_from_vulnerability(vulnerability: Dict[str, Any]) -> Optional[str]:
    vuln_id = vulnerability.get("id") or ""
    if vuln_id.startswith("CVE-"):
        return vuln_id
    for alias in vulnerability.get("aliases") or []:
        if alias.startswith("CVE-"):
            return alias
    return None


def extract_fixed_versions(vulnerability: Dict[str, Any]) -> List[str]:
    fixed: List[str] = []
    for affected in vulnerability.get("affected") or []:
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if "fixed" in event:
                    fixed.append(event["fixed"])
    seen: set = set()
    ordered: List[str] = []
    for v in fixed:
        if v not in seen:
            seen.add(v)
            ordered.append(v)
    return ordered


def _cvss3_base_score(vector: str) -> Optional[float]:
    """Standard CVSS v3.x base-score formula, computed from a bare vector
    string (OSV's `severity[].score` for CVSS_V3/CVSS_V4 entries is a vector,
    not a number). Returns None for anything that isn't a well-formed v3.x
    vector — callers fall back to `database_specific.severity` or UNKNOWN."""
    if not vector or "CVSS:3" not in vector:
        return None
    parts: Dict[str, str] = {}
    for segment in vector.split("/"):
        if ":" not in segment:
            continue
        k, v = segment.split(":", 1)
        parts[k] = v
    try:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[parts["AV"]]
        ac = {"L": 0.77, "H": 0.44}[parts["AC"]]
        ui = {"N": 0.85, "R": 0.62}[parts["UI"]]
        scope_changed = parts.get("S") == "C"
        pr_table = (
            {"N": 0.85, "L": 0.68, "H": 0.50}
            if scope_changed
            else {"N": 0.85, "L": 0.62, "H": 0.27}
        )
        pr = pr_table[parts["PR"]]
        cia = {"H": 0.56, "L": 0.22, "N": 0.0}
        c, i, a = cia[parts["C"]], cia[parts["I"]], cia[parts["A"]]
    except KeyError:
        return None

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    exploitability = 8.22 * av * ac * pr * ui
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    score = 1.08 * (impact + exploitability) if scope_changed else impact + exploitability
    score = min(score, 10.0)
    return math.ceil(score * 10) / 10


def extract_cvss_score(vulnerability: Dict[str, Any]) -> Tuple[Optional[float], str]:
    """Returns ``(score, source)``. Tries every `severity[]` entry OSV
    supplies — CVSS v3.x vectors first, falling back to a bare numeric score
    on the rare entry that already carries one."""
    for entry in vulnerability.get("severity") or []:
        raw = entry.get("score") or ""
        score = _cvss3_base_score(raw)
        if score is not None:
            return score, entry.get("type", "osv")
        try:
            return float(raw), entry.get("type", "osv")
        except (TypeError, ValueError):
            continue
    return None, "none"


def get_severity(
    cvss_score: Optional[float], database_specific: Optional[Dict[str, Any]] = None
) -> str:
    if database_specific:
        label = str(database_specific.get("severity") or "").upper()
        if label == "MODERATE":  # GHSA's label for what we call MEDIUM
            label = "MEDIUM"
        if label in _SEVERITY_ORDER:
            return label
    if cvss_score is None:
        return "UNKNOWN"
    if cvss_score >= 9.0:
        return "CRITICAL"
    if cvss_score >= 7.0:
        return "HIGH"
    if cvss_score >= 4.0:
        return "MEDIUM"
    return "LOW"


# ===========================================================================
# Finding construction
# ===========================================================================


def build_findings(dependencies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Runs OSV batch + detail lookups against `dependencies`
    (``{"ecosystem","name","version","source_file",...}``) and returns a flat
    list of `Finding`-shaped dicts (``kind="sca"``), sorted by severity."""
    findings: List[Dict[str, Any]] = []
    hits_by_index = query_osv_batch(dependencies)
    for index, stubs in hits_by_index.items():
        dependency = dependencies[index]
        for stub in stubs[:MAX_VULNS_PER_DEPENDENCY]:
            full = get_full_osv_vulnerability(stub.get("id")) or stub
            cve = extract_cve_from_vulnerability(full)
            cvss_score, _cvss_source = extract_cvss_score(full)
            severity = get_severity(cvss_score, full.get("database_specific"))
            fixed_versions = extract_fixed_versions(full)
            vuln_id = full.get("id") or stub.get("id") or "UNKNOWN"
            rule_id = cve or vuln_id
            summary = (full.get("summary") or full.get("details") or "").strip()
            pkg_label = f"{dependency['name']}@{dependency.get('version') or 'unknown'}"
            ai_fix = (
                f"Upgrade {dependency['name']} to {fixed_versions[0]} or later."
                if fixed_versions
                else "No fixed version published yet — track the advisory for an upgrade path."
            )
            title = f"{pkg_label} — {rule_id} ({severity})"
            if summary:
                title += f": {summary[:160]}"
            findings.append(
                {
                    "severity": severity,
                    "cvss": cvss_score,
                    "rule_id": rule_id,
                    "title": title[:500],
                    "file_path": dependency.get("source_file"),
                    # The bare "name@version" the OSV match is against — kept
                    # separate from `title` the same way regex findings keep
                    # `matched_text` separate from the full title, so the same
                    # scan_export/group_findings_by_issue grouping keys work
                    # unmodified for kind="sca" rows.
                    "matched_text": pkg_label[:500],
                    "snippet": summary[:2000] if summary else None,
                    "kind": "sca",
                    # No LLM/human review step in v1 — an OSV hit is a factual
                    # version-range match, not yet reviewed for exploitability
                    # in this codebase, mirroring the "pattern matched, nobody
                    # reviewed it" semantics regex-only findings already use.
                    "verdict": "unverified",
                    "unresolved_reason": "not_reviewed_sca",
                    "ai_fix": ai_fix,
                }
            )
    findings.sort(key=lambda f: _SEVERITY_RANK.get(f["severity"], len(_SEVERITY_RANK)))
    return findings


def _severity_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {level: 0 for level in _SEVERITY_ORDER}
    for f in findings:
        level = f.get("severity", "UNKNOWN")
        counts[level] = counts.get(level, 0) + 1
    return counts


# ===========================================================================
# Orchestration
# ===========================================================================


def run_sca_scan(
    repo_root: Path,
    findings_writer: Optional[Callable[[str, List[dict]], None]] = None,
    discovery_writer: Optional[Callable[[dict], None]] = None,
) -> Dict[str, Any]:
    """Orchestrates collect_dependencies -> OSV lookup -> findings, writing
    incrementally via the same writer callbacks the SAST engine uses
    (`scan_runner._make_findings_writer` / `_make_discovery_writer`)."""
    dependencies = collect_dependencies(repo_root)
    findings = build_findings(dependencies)

    # Group findings by manifest file so findings_writer's per-file contract
    # (one call per scanned "file") is respected the same way the SAST
    # engine's deep/triage scan tiers call it.
    findings_by_file: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        findings_by_file.setdefault(f.get("file_path") or "", []).append(f)

    if findings_writer:
        for file_path, file_findings in findings_by_file.items():
            findings_writer(file_path, file_findings)

    vulnerable_names = {f["matched_text"].rsplit("@", 1)[0] for f in findings if f.get("matched_text")}
    discovery = {
        "dependency_summary": {
            "total_dependencies": len(dependencies),
            "vulnerable_dependencies": len(vulnerable_names),
            "manifests_parsed": sorted(
                {d["source_file"] for d in dependencies if d.get("source_file")}
            ),
            "ecosystems": sorted({d["ecosystem"] for d in dependencies}),
            "severity_counts": _severity_counts(findings),
        },
        "dependencies": dependencies,
    }
    if discovery_writer:
        discovery_writer(discovery)

    return {"discovery": discovery, "usage_summary": None}
