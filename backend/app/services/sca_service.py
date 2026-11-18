"""SCA / VEX analysis via OSV.dev batch API.

Takes a list of CycloneDX component dicts (each with a 'purl' field) and
returns a list of vulnerability findings + a VEX applicability summary.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("sca.service")

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_BATCH_SIZE = 50  # OSV.dev recommendation: ≤ 1000 queries per request


def run_sca(components: list[dict]) -> dict:
    """Query OSV.dev for known vulnerabilities across *components*.

    Returns::

        {
            "vulnerabilities": [
                {
                    "purl": str,
                    "package_name": str,
                    "version": str,
                    "vulns": [{"id": str, "summary": str, "severity": str, ...}],
                },
                ...
            ],
            "vex_statements": [
                {"purl": str, "vuln_id": str, "status": str, "justification": str},
                ...
            ],
            "component_count": int,
            "vulnerable_component_count": int,
        }

    On network/unhandled failure returns the same structure with empty lists.
    """
    try:
        import httpx
    except ImportError:
        logger.warning("httpx not installed; SCA scan skipped")
        return _empty_result(components)

    purls = [c.get("purl", "") for c in components if c.get("purl")]
    if not purls:
        return _empty_result(components)

    all_results: list[dict | None] = []
    try:
        for batch_start in range(0, len(purls), _BATCH_SIZE):
            batch = purls[batch_start : batch_start + _BATCH_SIZE]
            queries = [{"package": {"purl": p}} for p in batch]
            payload = {"queries": queries}
            with httpx.Client(timeout=30.0) as client:
                resp = client.post(_OSV_BATCH_URL, json=payload)
                resp.raise_for_status()
            results = resp.json().get("results", [])
            all_results.extend(results)
    except Exception as exc:
        logger.warning("OSV.dev batch query failed: %s", exc)
        return _empty_result(components)

    vulnerabilities: list[dict] = []
    vex_statements: list[dict] = []

    for purl, result in zip(purls, all_results):
        if not result:
            continue
        vulns_raw = result.get("vulns") or []
        if not vulns_raw:
            continue

        # Find matching component metadata
        comp = next((c for c in components if c.get("purl") == purl), {})
        pkg_name = comp.get("name") or purl
        version = comp.get("version", "")

        normalized_vulns = []
        for v in vulns_raw:
            vuln_id = v.get("id", "")
            summary = v.get("summary", "")
            aliases = v.get("aliases", [])
            severity = _extract_severity(v)

            normalized_vulns.append({
                "id": vuln_id,
                "aliases": aliases,
                "summary": summary,
                "severity": severity,
                "cwe_ids": _extract_cwe_ids(v),
                "details": v.get("details", ""),
                "references": [r.get("url", "") for r in (v.get("references") or []) if r.get("url")],
                "published": v.get("published", ""),
                "modified": v.get("modified", ""),
            })

            # Generate a VEX statement — default status "affected" unless a fix exists
            status = "affected"
            justification = ""
            fixed_versions = _get_fixed_versions(v)
            if fixed_versions:
                status = "fixed"
                justification = f"Fixed in: {', '.join(fixed_versions[:3])}"

            vex_statements.append({
                "purl": purl,
                "vuln_id": vuln_id,
                "status": status,
                "justification": justification,
            })

        vulnerabilities.append({
            "purl": purl,
            "package_name": pkg_name,
            "version": version,
            "vuln_count": len(normalized_vulns),
            "vulns": normalized_vulns,
        })

    return {
        "vulnerabilities": vulnerabilities,
        "vex_statements": vex_statements,
        "component_count": len(purls),
        "vulnerable_component_count": len(vulnerabilities),
    }


def _empty_result(components: list[dict]) -> dict:
    return {
        "vulnerabilities": [],
        "vex_statements": [],
        "component_count": len([c for c in components if c.get("purl")]),
        "vulnerable_component_count": 0,
    }


def _extract_severity(vuln: dict[str, Any]) -> str:
    """Best-effort CVSS severity from an OSV vuln record.

    OSV ``severity[].score`` is a CVSS *vector* string (e.g.
    ``CVSS:3.1/AV:N/AC:L/…``), not a numeric base score.  We parse the
    ``CVSS:x.x/`` prefix and read the named sub-metrics that together define
    the base score band rather than trying to parse the full formula.
    If that fails we fall back to ``database_specific.severity`` (GHSA and
    NVD both populate this as a plain ``HIGH`` / ``CRITICAL`` string).
    """
    for sev in vuln.get("severity") or []:
        score = sev.get("score", "")
        # Numeric score (rare but possible in some ecosystem DBs)
        try:
            base = float(score)
            if base >= 9.0:
                return "CRITICAL"
            if base >= 7.0:
                return "HIGH"
            if base >= 4.0:
                return "MEDIUM"
            return "LOW"
        except (ValueError, TypeError):
            pass
        # CVSS vector string — derive severity from the CVSS base score band
        # encoded in the vector itself (the numeric score is not in the string
        # but the band is implied by the sub-metrics).
        if score.startswith("CVSS:") and "/" in score:
            band = _cvss_vector_band(score)
            if band:
                return band
    # database_specific.severity is the most reliable plain-text field
    db_specific = vuln.get("database_specific") or {}
    cve_severity = db_specific.get("severity") or db_specific.get("cvss_v3_severity") or ""
    if cve_severity and cve_severity.upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return cve_severity.upper()
    return "MEDIUM"  # safer default than UNKNOWN for display purposes


def _cvss_vector_band(vector: str) -> str:
    """Return a severity band from a CVSS v3/v4 vector string.

    Uses a simplified heuristic: if any of the high-impact metrics are set
    to their worst values, the finding is at least HIGH.  This avoids a full
    CVSS base-score calculation while still being directionally correct for
    the most common vectors.
    """
    parts = {k: v for part in vector.split("/")[1:] for k, v in [part.split(":", 1)] if ":" in part}
    # C (Confidentiality), I (Integrity), A (Availability) impact
    high_impact = sum(1 for m in ("C", "I", "A") if parts.get(m) == "H")
    if high_impact >= 3:
        return "CRITICAL"
    if high_impact >= 2:
        return "HIGH"
    if high_impact >= 1:
        return "HIGH" if parts.get("AV") in ("N", "A") else "MEDIUM"
    return "MEDIUM"


def _extract_cwe_ids(vuln: dict[str, Any]) -> list[str]:
    """Extract CWE IDs from an OSV vulnerability record.

    GitHub Advisory Database (GHSA) records carry CWEs in
    ``database_specific.cwe_ids`` as a list of ``"CWE-NNN"`` strings.
    NVD records occasionally carry them in ``affected[].database_specific``.
    """
    db_specific = vuln.get("database_specific") or {}
    cwe_ids: list[str] = list(db_specific.get("cwe_ids") or [])
    if not cwe_ids:
        for affected in vuln.get("affected") or []:
            for cwe in (affected.get("database_specific") or {}).get("cwe_ids") or []:
                if cwe not in cwe_ids:
                    cwe_ids.append(cwe)
    return cwe_ids


def _get_fixed_versions(vuln: dict[str, Any]) -> list[str]:
    """Collect fix versions from OSV affected ranges."""
    fixed: list[str] = []
    for affected in vuln.get("affected") or []:
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                v = event.get("fixed")
                if v:
                    fixed.append(v)
    return fixed
