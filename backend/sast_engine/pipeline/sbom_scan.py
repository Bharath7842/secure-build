"""sbom_scan.py — deterministic SBOM (Software Bill of Materials) pipeline.

MVP + license-classification scope: reuses `sca_scan.collect_dependencies`
for manifest discovery, builds a PURL per dependency, does a best-effort
single-lookup license classification against deps.dev plus a small static
data set (ported from a reference SBOM app — see `license_data/`), and
emits CycloneDX 1.5 + SPDX 2.3 JSON documents. Pure Python (stdlib +
`requests`) — no LangGraph, no LLM, no boto3, no cdxgen — so it never needs
the dynamic `agent_bridge` loader the SAST engine requires, and the
mock-engine test suite never touches it at all unless a test explicitly
imports it.

Explicitly deferred (mirrors the SCA MVP's own deferred list): cdxgen-based
dependency graphs, lockfile/transitive dependency resolution (every
component is reported `direct=True`), license-file text parsing,
ClearlyDefined enrichment, SPDX-license-list validation, HTML/PDF reports,
drift comparison, and continuous-monitoring webhooks. All of those can layer
on top of this module later without touching its public functions.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import quote

import requests

from . import sca_scan

_LICENSE_DATA_DIR = Path(__file__).resolve().parent / "license_data"

DEPSDEV_BASE = "https://api.deps.dev/v3alpha"
DEPSDEV_TIMEOUT = 15

# manifest_parsers.py's lowercase ecosystem key -> deps.dev's system name.
# rubygems/packagist aren't supported by deps.dev — lookups for those
# ecosystems are skipped and fall back to "unknown".
_DEPSDEV_SYSTEM_MAP = {
    "npm": "NPM",
    "pypi": "PYPI",
    "cratesio": "CARGO",
    "maven": "MAVEN",
    "go": "GOLANG",
    "nuget": "NUGET",
}

# manifest_parsers.py's lowercase ecosystem key -> PackageURL type.
_PURL_TYPE_MAP = {
    "maven": "maven",
    "npm": "npm",
    "pypi": "pypi",
    "go": "golang",
    "rubygems": "gem",
    "packagist": "composer",
    "nuget": "nuget",
    "cratesio": "cargo",
}

_COST_ORDER = ("fully_free", "partially_free", "fully_paid", "unknown")


def _load_json(filename: str) -> Any:
    path = _LICENSE_DATA_DIR / filename
    with path.open(encoding="utf-8") as f:
        return json.load(f)


LICENSE_ALIASES: Dict[str, str] = _load_json("license_aliases.json")
KNOWN_LICENSES: Dict[str, Dict[str, str]] = _load_json("known_licenses.json")
VENDOR_EDITIONS: Dict[str, Dict[str, Any]] = _load_json("vendor_editions.json")

# open_source_indicators.json / proprietary_patterns.json are loaded for
# completeness with the reference app's data set, but this module never does
# license-file text scanning (deferred — see module docstring), so they are
# not consulted by any function below yet.


# ===========================================================================
# PURL generation
# ===========================================================================


def build_purl(dependency: Dict[str, Any]) -> Optional[str]:
    """Builds a `pkg:<type>/...@<version>` PackageURL for a dependency dict
    shaped like `sca_scan.collect_dependencies`'s output
    (`ecosystem`/`name`/`version`). Returns None when the ecosystem has no
    known PURL type or the dependency has no version."""
    ecosystem = dependency.get("ecosystem")
    name = dependency.get("name") or ""
    version = dependency.get("version")
    purl_type = _PURL_TYPE_MAP.get(ecosystem)
    if not purl_type or not name or not version:
        return None

    if purl_type == "maven":
        if ":" in name:
            group, _, artifact = name.partition(":")
            return f"pkg:maven/{quote(group, safe='')}/{quote(artifact, safe='')}@{quote(version, safe='')}"
        return f"pkg:maven/{quote(name, safe='')}@{quote(version, safe='')}"

    if purl_type == "npm":
        if name.startswith("@") and "/" in name:
            scope, _, pkg = name.partition("/")
            return f"pkg:npm/{quote(scope, safe='')}/{quote(pkg, safe='')}@{quote(version, safe='')}"
        return f"pkg:npm/{quote(name, safe='')}@{quote(version, safe='')}"

    if purl_type == "pypi":
        return f"pkg:pypi/{quote(name, safe='.-_')}@{quote(version, safe='')}"

    if purl_type == "golang":
        return f"pkg:golang/{quote(name, safe='/')}@{quote(version, safe='')}"

    if purl_type == "composer":
        return f"pkg:composer/{quote(name, safe='/')}@{quote(version, safe='')}"

    return f"pkg:{purl_type}/{quote(name, safe='')}@{quote(version, safe='')}"


# ===========================================================================
# deps.dev license lookup — network best-effort, single PURL per call
# ===========================================================================


def lookup_depsdev_license(purl: str) -> Optional[Dict[str, Any]]:
    """GETs `api.deps.dev/v3alpha/purl/{purl}` for declared-license metadata.
    Best-effort: any network/parse failure (or an unsupported ecosystem)
    returns None rather than raising — mirrors
    `sca_scan.get_full_osv_vulnerability`'s style."""
    purl_type = _extract_purl_type(purl)
    if purl_type not in _DEPSDEV_SYSTEM_MAP.values():
        return None
    try:
        resp = requests.get(
            f"{DEPSDEV_BASE}/purl/{quote(purl, safe='')}",
            headers={"Accept": "application/json"},
            timeout=DEPSDEV_TIMEOUT,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
    except (requests.RequestException, ValueError):
        return None

    # The purl lookup endpoint nests version metadata (including licenses)
    # under a "version" key rather than at the top level — missing this
    # unwrap silently produced empty licenses/license_details for every
    # single lookup, which is why every component used to show "unknown".
    version_data = data.get("version") or {}
    licenses = version_data.get("licenses") or []
    license_details = version_data.get("licenseDetails") or []
    spdx_id = ""
    raw_license = ""
    if license_details:
        for detail in license_details:
            spdx = detail.get("spdx", "")
            if spdx and spdx != "non-standard":
                spdx_id = spdx
                raw_license = detail.get("license", "")
                break
        if not spdx_id:
            raw_license = license_details[0].get("license", "")
    elif licenses:
        for lic in licenses:
            if lic and lic != "non-standard":
                spdx_id = lic
                raw_license = lic
                break
    return {"spdx_id": spdx_id, "raw_license": raw_license}


_PURL_TYPE_TO_DEPSDEV_SYSTEM = {
    "npm": "NPM", "pypi": "PYPI", "cargo": "CARGO",
    "maven": "MAVEN", "golang": "GOLANG", "nuget": "NUGET",
}


def _extract_purl_type(purl: str) -> str:
    """Returns the deps.dev *system* name (e.g. "NPM") for a `pkg:npm/...`
    PURL, or "" if unrecognized — matches `_DEPSDEV_SYSTEM_MAP` values so
    callers can check membership directly."""
    if not purl.startswith("pkg:"):
        return ""
    remainder = purl[4:]
    slash = remainder.find("/")
    if slash <= 0:
        return ""
    purl_type = remainder[:slash]
    return _PURL_TYPE_TO_DEPSDEV_SYSTEM.get(purl_type, "")


# ===========================================================================
# License classification
# ===========================================================================


def _normalize_pkg_name(name: str) -> str:
    normalized = name.lower()
    if "/" in normalized:
        normalized = normalized.split("/")[-1]
    if normalized.startswith("@"):
        parts = normalized.split("/")
        if len(parts) > 1:
            normalized = parts[-1]
    return normalized


def _resolve_spdx(license_str: str) -> Optional[Dict[str, str]]:
    """Resolves a raw license string/SPDX-id-ish string to a
    `{spdx_id, name, type}` dict via `KNOWN_LICENSES`/`LICENSE_ALIASES`.
    Returns None when nothing matches (caller falls back to unknown)."""
    if not license_str:
        return None
    lowered = license_str.lower().strip()
    normalized = re.sub(r"\s+", " ", lowered)

    for alias, spdx_id in LICENSE_ALIASES.items():
        if alias.lower() in (normalized, lowered):
            info = KNOWN_LICENSES.get(spdx_id.lower())
            if info:
                return {"spdx_id": info["spdx_id"], "name": info["name"], "type": info["type"]}

    for spdx_id, info in KNOWN_LICENSES.items():
        if spdx_id == lowered or info["name"].lower() == lowered:
            return {"spdx_id": info["spdx_id"], "name": info["name"], "type": info["type"]}

    # Substring fallback — a raw SPDX-ish token embedded in a longer string.
    for spdx_id, info in KNOWN_LICENSES.items():
        if spdx_id in lowered:
            return {"spdx_id": info["spdx_id"], "name": info["name"], "type": info["type"]}
    for alias, target_spdx in LICENSE_ALIASES.items():
        if alias in lowered:
            info = KNOWN_LICENSES.get(target_spdx.lower())
            if info:
                return {"spdx_id": info["spdx_id"], "name": info["name"], "type": info["type"]}
    return None


def _cost_classification(license_type: str, vendor_info: Optional[Dict[str, Any]]) -> str:
    if license_type == "proprietary":
        return "fully_paid"
    if vendor_info:
        edition = vendor_info.get("edition")
        if edition == "commercial_only":
            return "fully_paid"
        if vendor_info.get("paid_features"):
            return "partially_free"
    if license_type in ("permissive", "public_domain"):
        return "fully_free"
    if license_type in ("copyleft", "weak_copyleft"):
        return "partially_free"
    return "unknown"


def classify_license(
    dependency: Dict[str, Any], depsdev_result: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    """Best-effort license + cost-bucket classification for one dependency.

    Resolution order: deps.dev-returned SPDX id -> a declared license string
    on the dependency itself (manifest parsers don't currently supply one,
    but this stays forward-compatible) -> unknown. Vendor/edition/paid-
    feature signal comes from the static `VENDOR_EDITIONS` table, keyed by
    normalized package name. No license-file scanning, no ClearlyDefined
    call, no confidence-based revalidation — see module docstring."""
    resolved: Optional[Dict[str, str]] = None
    if depsdev_result and depsdev_result.get("spdx_id"):
        resolved = _resolve_spdx(depsdev_result["spdx_id"])
    if resolved is None and dependency.get("license"):
        resolved = _resolve_spdx(str(dependency["license"]))

    if resolved is None:
        spdx_id, license_name, license_type = "LicenseRef-unknown", "Unknown License", "unknown"
    else:
        spdx_id, license_name, license_type = resolved["spdx_id"], resolved["name"], resolved["type"]

    normalized_name = _normalize_pkg_name(dependency.get("name") or "")
    vendor_info = VENDOR_EDITIONS.get(normalized_name)
    vendor = vendor_info.get("vendor") if vendor_info else None
    cost_classification = _cost_classification(license_type, vendor_info)

    return {
        "spdx_id": spdx_id,
        "license_name": license_name,
        "license_type": license_type,
        "vendor": vendor,
        "cost_classification": cost_classification,
    }


# ===========================================================================
# Component / CycloneDX / SPDX builders
# ===========================================================================


def _default_origin_type(license_type: str) -> str:
    """Deterministic "Open Source" / "Proprietary" fallback for the `origin_type`
    column, used before (and, if LLM enrichment is off or fails, instead of)
    the LLM's per-package answer. Nothing in the deterministic pipeline can
    positively identify an "Internal" package — see `llm_enrich_components`."""
    return "Proprietary" if license_type == "proprietary" else "Open Source"


def _dependency_relationship_label(scope: Optional[str]) -> str:
    """`Dependency Relationship` column value. Every component here is a
    direct, manifest-declared dependency (no lockfile/transitive resolution —
    see module docstring), so this only ever qualifies *how* it's direct."""
    key = (scope or "runtime").strip().lower()
    if key in ("dev", "test"):
        return "Direct (Dev)"
    if key == "peer":
        return "Direct (Peer)"
    if key == "provided":
        return "Direct (Provided)"
    return "Direct"


def build_components(
    dependencies: List[Dict[str, Any]], license_by_purl: Dict[str, Dict[str, Any]]
) -> List[Dict[str, Any]]:
    components: List[Dict[str, Any]] = []
    for dep in dependencies:
        purl = build_purl(dep)
        group = None
        name = dep.get("name") or ""
        if dep.get("ecosystem") == "maven" and ":" in name:
            group, _, name = name.partition(":")
        license_info = license_by_purl.get(purl) if purl else None
        components.append(
            {
                "bom-ref": purl or f"{dep.get('ecosystem')}:{dep.get('name')}@{dep.get('version')}",
                "type": "library",
                "name": name,
                "version": dep.get("version"),
                "purl": purl,
                "group": group,
                "ecosystem": dep.get("ecosystem"),
                "scope": dep.get("scope") or "runtime",
                "source_file": dep.get("source_file"),
                "licenses": (
                    [{"spdx_id": license_info["spdx_id"], "name": license_info["license_name"]}]
                    if license_info
                    else []
                ),
                "cost_classification": license_info["cost_classification"] if license_info else "unknown",
                "vendor": license_info.get("vendor") if license_info else None,
                "origin_type": _default_origin_type(license_info["license_type"] if license_info else "unknown"),
                "dependency_relationship": _dependency_relationship_label(dep.get("scope")),
                "direct": True,
            }
        )
    return components


# ===========================================================================
# LLM enrichment (Bedrock Claude Haiku) — best-effort supplier/license/type
# fill-in for whatever the deterministic deps.dev + static-table pass above
# left unresolved.
# ===========================================================================

_LLM_ENRICH_BATCH_SIZE = 30
_LLM_ENRICH_STEP = "sbom_enrich"

_ENRICH_SYSTEM_PROMPT = """You are a software supply-chain expert. For each package \
listed, use your general knowledge of well-known open-source and commercial package \
ecosystems (npm, PyPI, Maven, Go modules, NuGet, RubyGems, Packagist, crates.io) to \
identify:

- "license": the package's SPDX license identifier (e.g. "MIT", "Apache-2.0", \
"GPL-3.0-only"). Use "Unknown" only if you genuinely do not recognize the package.
- "supplier": the organization, company, or foundation that publishes/maintains the \
package (e.g. "Meta / OpenJS", "Apache Software Foundation", "Vitest Team"). Use \
"Open Source Community" if it is clearly open source but you don't know a specific \
maintaining org, or "Unknown" if you don't recognize the package at all.
- "type": one of "Open Source", "Proprietary", or "Internal" — "Proprietary" only for \
packages you know to be commercially licensed / closed-source, "Internal" only if the \
name strongly suggests a private internal package, otherwise "Open Source".

Respond with strict JSON only, no prose, matching exactly this shape:
{"components": [{"index": <int>, "license": "<string>", "supplier": "<string>", "type": "<string>"}, ...]}

Include exactly one entry per input component, reusing its "index" value. Do not invent
packages that are not in the input list."""


def _get_llm_client():
    """Lazy import so `sast_engine.llm_client` (and its Bedrock client
    construction) is only touched when LLM enrichment actually runs —
    mirrors `agent_bridge.py`'s lazy-import convention for real-engine-only
    dependencies, keeping the deterministic mock/live paths import-cheap."""
    from sast_engine import llm_client

    return llm_client


def _needs_enrichment(comp: Dict[str, Any]) -> bool:
    licenses = comp.get("licenses") or []
    spdx = licenses[0].get("spdx_id") if licenses else None
    return not comp.get("vendor") or spdx in (None, "", "LicenseRef-unknown")


def _prompt_component_name(comp: Dict[str, Any]) -> str:
    group = (comp.get("group") or "").strip()
    name = (comp.get("name") or "").strip()
    return f"{group}:{name}" if group else name


def _apply_llm_enrichment(comp: Dict[str, Any], entry: Dict[str, Any]) -> None:
    license_value = str(entry.get("license") or "").strip()
    supplier_value = str(entry.get("supplier") or "").strip()
    type_value = str(entry.get("type") or "").strip()

    licenses = comp.get("licenses") or []
    spdx = licenses[0].get("spdx_id") if licenses else None
    if spdx in (None, "", "LicenseRef-unknown") and license_value and license_value.lower() != "unknown":
        resolved = _resolve_spdx(license_value)
        if resolved:
            comp["licenses"] = [{"spdx_id": resolved["spdx_id"], "name": resolved["name"]}]
            if comp.get("cost_classification") == "unknown":
                comp["cost_classification"] = _cost_classification(resolved["type"], None)
        else:
            comp["licenses"] = [{"spdx_id": license_value, "name": license_value}]

    if not comp.get("vendor") and supplier_value and supplier_value.lower() != "unknown":
        comp["vendor"] = supplier_value

    if type_value:
        comp["origin_type"] = type_value

    comp["llm_enriched"] = True


def llm_enrich_components(
    components: List[Dict[str, Any]],
    *,
    usage: Optional[Dict[str, Any]] = None,
    provider: Optional[str] = None,
    model: Optional[str] = None,
) -> None:
    """Best-effort supplier/license/type enrichment via Bedrock Claude Haiku
    for components the deterministic deps.dev + static-table pass above left
    with no known supplier and/or no resolved license. Mutates `components`
    in place; any import/network/parse failure is swallowed so a scan never
    fails because of this step — the deterministic fields already on each
    component are always the floor, never overwritten by a worse LLM answer."""
    targets = [(idx, comp) for idx, comp in enumerate(components) if _needs_enrichment(comp)]
    if not targets:
        return

    try:
        llm_client = _get_llm_client()
    except Exception:
        return

    for start in range(0, len(targets), _LLM_ENRICH_BATCH_SIZE):
        batch = targets[start : start + _LLM_ENRICH_BATCH_SIZE]
        by_index = {idx: comp for idx, comp in batch}
        user_prompt = json.dumps(
            {
                "components": [
                    {
                        "index": idx,
                        "name": _prompt_component_name(comp),
                        "ecosystem": comp.get("ecosystem") or "",
                        "version": comp.get("version") or "",
                    }
                    for idx, comp in batch
                ]
            },
            indent=2,
        )
        try:
            raw = llm_client.call_llm(
                _ENRICH_SYSTEM_PROMPT,
                user_prompt,
                max_tokens=2048,
                usage=usage,
                step=_LLM_ENRICH_STEP,
                provider=provider or "bedrock",
                model=model,
                json_mode=True,
            )
            parsed, err = llm_client.parse_llm_json_dict(raw)
        except Exception:
            continue
        if err or not isinstance(parsed, dict):
            continue
        entries = parsed.get("components")
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            try:
                idx = int(entry.get("index"))
            except (TypeError, ValueError):
                continue
            comp = by_index.get(idx)
            if comp is not None:
                _apply_llm_enrichment(comp, entry)


def build_cyclonedx_sbom(components: List[Dict[str, Any]], scan_id: str) -> Dict[str, Any]:
    """Trimmed CycloneDX 1.5 JSON document — root "application" component,
    `metadata.tools`/`properties`, per-component `licenses`. No `evidence`
    or integrity-hash properties (deferred, see module docstring)."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    cdx_components = []
    for comp in components:
        cdx_comp: Dict[str, Any] = {
            "bom-ref": comp["bom-ref"],
            "type": comp.get("type", "library"),
            "name": comp["name"],
            "version": comp.get("version") or "",
            "purl": comp.get("purl") or "",
        }
        if comp.get("group"):
            cdx_comp["group"] = comp["group"]
        cdx_comp["properties"] = [
            {"name": "ecosystem", "value": comp.get("ecosystem") or ""},
            {"name": "scope", "value": comp.get("scope") or "runtime"},
            {"name": "direct", "value": str(comp.get("direct", True))},
            {"name": "cost_classification", "value": comp.get("cost_classification") or "unknown"},
        ]
        if comp.get("source_file"):
            cdx_comp["properties"].append({"name": "source_file", "value": comp["source_file"]})
        if comp.get("licenses"):
            lic = comp["licenses"][0]
            license_entry: Dict[str, str] = {}
            if lic.get("spdx_id") and lic["spdx_id"] != "LicenseRef-unknown":
                license_entry["id"] = lic["spdx_id"]
            license_entry["name"] = lic.get("name", "Unknown License")
            cdx_comp["licenses"] = [{"license": license_entry}]
        cdx_components.append(cdx_comp)

    root_ref = f"sbom-root-{scan_id}"
    root_component = {
        "bom-ref": root_ref,
        "type": "application",
        "name": "scanned-project",
        "version": "1.0.0",
        "purl": "pkg:generic/scanned-project@1.0.0",
    }

    sbom: Dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "serialNumber": f"urn:uuid:{scan_id}",
        "metadata": {
            "timestamp": now,
            "tools": [{"vendor": "augmented-secure-build", "name": "sbom-scan", "version": "1.0.0"}],
            "component": root_component,
            "properties": [
                {"name": "scan_id", "value": scan_id},
                {"name": "spec_version", "value": "1.5"},
            ],
        },
        "components": cdx_components,
        "dependencies": [
            {"ref": root_ref, "dependsOn": [c["bom-ref"] for c in cdx_components if comp_is_direct(c)]}
        ],
    }
    return sbom


def comp_is_direct(cdx_component: Dict[str, Any]) -> bool:
    for prop in cdx_component.get("properties") or []:
        if prop.get("name") == "direct":
            return str(prop.get("value")).lower() == "true"
    return True


def build_spdx_sbom(components: List[Dict[str, Any]], scan_id: str) -> Dict[str, Any]:
    """Trimmed SPDX 2.3 JSON document — root package + `CONTAINS`
    relationships only (no `DEPENDS_ON` edges, no dependency graph in v1)."""
    doc_namespace = f"urn:uuid:{scan_id}"
    creation_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    root_pkg_id = "SPDXRef-Package-0"
    packages: List[Dict[str, Any]] = [
        {
            "SPDXID": root_pkg_id,
            "name": "scanned-project",
            "downloadLocation": "NOASSERTION",
            "versionInfo": "1.0.0",
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "checksums": [],
            "externalRefs": [],
            "description": "",
            "primaryPackagePurpose": "APPLICATION",
        }
    ]
    relationships: List[Dict[str, Any]] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relatedSpdxElement": root_pkg_id,
            "relationshipType": "DESCRIBES",
        }
    ]

    for i, comp in enumerate(components):
        pkg_id = f"SPDXRef-Package-{i + 1}"
        licenses = comp.get("licenses") or []
        spdx_lic = licenses[0]["spdx_id"] if licenses and licenses[0].get("spdx_id") else "LicenseRef-unknown"
        external_refs = []
        if comp.get("purl"):
            external_refs.append(
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": comp["purl"],
                }
            )
        packages.append(
            {
                "SPDXID": pkg_id,
                "name": comp.get("name") or "",
                "downloadLocation": "NOASSERTION",
                "versionInfo": comp.get("version") or "",
                "licenseConcluded": spdx_lic,
                "licenseDeclared": spdx_lic,
                "copyrightText": "NOASSERTION",
                "checksums": [],
                "externalRefs": external_refs,
                "description": "",
                "primaryPackagePurpose": "LIBRARY",
            }
        )
        relationships.append(
            {
                "spdxElementId": root_pkg_id,
                "relatedSpdxElement": pkg_id,
                "relationshipType": "CONTAINS",
            }
        )

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"SBOM-{scan_id}",
        "documentNamespace": doc_namespace,
        "creationInfo": {
            "created": creation_time,
            "creators": ["Tool: sbom-scan", "Organization: augmented-secure-build"],
            "licenseListVersion": "3.21",
        },
        "documentDescribes": [root_pkg_id],
        "packages": packages,
        "relationships": relationships,
    }


# ===========================================================================
# Orchestration
# ===========================================================================


def _license_summary(components: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {level: 0 for level in _COST_ORDER}
    for comp in components:
        level = comp.get("cost_classification", "unknown")
        counts[level] = counts.get(level, 0) + 1
    return counts


def run_sbom_scan(
    repo_root: Path,
    scan_id: Optional[str] = None,
    discovery_writer: Optional[Callable[[dict], None]] = None,
    *,
    use_llm_enrichment: bool = False,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
) -> Dict[str, Any]:
    """Orchestrates collect_dependencies -> purl -> deps.dev license lookup
    -> classify -> CycloneDX/SPDX build, writing the discovery payload via
    the same writer-callback contract `sca_scan.run_sca_scan` uses. Produces
    no `Finding` rows — SBOM has no vulnerability-detection step of its own
    (that's SCA's job).

    `use_llm_enrichment` (off by default — the whole test suite exercises
    this function directly with the network/LLM unmocked) additionally runs
    `llm_enrich_components` over whatever deps.dev + the static tables left
    unresolved. `engine_adapter.run_sbom_scan` turns it on for real scans."""
    effective_scan_id = scan_id or "sbom-scan"
    dependencies = sca_scan.collect_dependencies(repo_root)

    license_by_purl: Dict[str, Dict[str, Any]] = {}
    for dep in dependencies:
        purl = build_purl(dep)
        if not purl:
            continue
        depsdev_result = lookup_depsdev_license(purl)
        license_by_purl[purl] = classify_license(dep, depsdev_result)

    components = build_components(dependencies, license_by_purl)

    llm_usage: Optional[Dict[str, Any]] = None
    if use_llm_enrichment and components:
        try:
            llm_client = _get_llm_client()
            llm_usage = llm_client.init_usage(provider=llm_provider or "bedrock", model=llm_model)
        except Exception:
            llm_usage = None
        llm_enrich_components(components, usage=llm_usage, provider=llm_provider or "bedrock", model=llm_model)

    sbom_cyclonedx = build_cyclonedx_sbom(components, effective_scan_id) if components else None
    sbom_spdx = build_spdx_sbom(components, effective_scan_id) if components else None

    discovery = {
        "component_summary": {
            "total_components": len(components),
            "ecosystems": sorted({c["ecosystem"] for c in components if c.get("ecosystem")}),
            "manifests_parsed": sorted({c["source_file"] for c in components if c.get("source_file")}),
            "license_summary": _license_summary(components),
        },
        "components": components,
        "sbom_cyclonedx": sbom_cyclonedx,
        "sbom_spdx": sbom_spdx,
    }
    if llm_usage is not None:
        try:
            discovery["llm_enrichment_usage"] = _get_llm_client().usage_cost_summary(llm_usage)
        except Exception:
            pass
    if discovery_writer:
        discovery_writer(discovery)

    return {"discovery": discovery}
