"""Deduplicate findings by fingerprint and retain detection provenance.

Four-pass deduplication:
  1. **Rule-mapping pass** – normalise rule_ids using the cross-scanner
     mapping so that equivalent rules from different scanners share
     the same canonical id before fingerprinting.
  2. **Fingerprint pass** – merge findings that share the exact same
     (canonical_rule_id, file_path, resource, line_start) fingerprint.
     This catches same-scanner duplicates and cross-scanner duplicates
     where the rule maps 1-to-1.
  3. **Cross-scanner pass** – group remaining findings by
     (normalised file_path, resource, severity, category) and merge
     findings that come from *different* scanners.  This catches
     semantically equivalent findings that different tools report under
     different rule_ids (e.g. trivy AWS-0173 vs checkov CKV_AWS_20
     for S3 public access).
  4. **Module-expansion pass** – merge Terraform module-reference findings
     (dotted resource like ``module.aws_instance.name``, empty file_path)
     with the direct-scan findings (plain resource name, real file_path)
     that result from the same module directory being scanned standalone.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

from app.services.iac_app.scanner.normalizer.finding_normalizer import (
    normalize_file_path,
    normalize_resource,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Rule mapping loader
# ---------------------------------------------------------------------------

_RULE_MAPPING_PATH = Path(__file__).parent / "rule_mapping.yaml"
_reverse_mapping: dict[str, str] = {}  # external_rule_id -> canonical_id


def _load_rule_mapping() -> dict[str, str]:
    """Load rule_mapping.yaml and build a reverse lookup.

    Returns a dict mapping every external scanner rule_id to its canonical
    internal rule_id.  The internal rule_id itself also maps to itself.
    """
    global _reverse_mapping
    if _reverse_mapping:
        return _reverse_mapping

    if not _RULE_MAPPING_PATH.exists():
        logger.warning("rule_mapping.yaml not found at %s", _RULE_MAPPING_PATH)
        return {}

    with open(_RULE_MAPPING_PATH, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}

    mappings = data.get("mappings", {})
    for canonical_id, aliases in mappings.items():
        _reverse_mapping[canonical_id] = canonical_id
        for alias in aliases:
            _reverse_mapping[alias] = canonical_id

    logger.debug("Loaded %s rule mappings", len(_reverse_mapping))
    return _reverse_mapping


def canonical_rule_id(rule_id: str | None) -> str | None:
    """Return the canonical internal rule_id for an external rule_id.

    If the rule_id is unknown it is returned unchanged.
    """
    if not rule_id:
        return rule_id
    mapping = _load_rule_mapping()
    return mapping.get(rule_id, rule_id)

RICH_FIELDS = [
    "description",
    "remediation",
    "evidence",
    "cwe",
    "owasp_category",
    "references",
    "compliance",
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def deduplicate_findings(findings: list[dict]) -> list[dict]:
    # Pass 0 – normalise rule_ids via the cross-scanner mapping
    for finding in findings:
        canonical = canonical_rule_id(finding.get("rule_id"))
        if canonical and canonical != finding.get("rule_id"):
            finding["canonical_rule_id"] = canonical

    # Pass 1 – fingerprint-based deduplication
    deduped = _deduplicate_by_fingerprint(findings)

    # Pass 2 – cross-scanner semantic deduplication
    deduped = _deduplicate_cross_scanner(deduped)

    # Pass 3 – Terraform module-expansion deduplication
    deduped = _deduplicate_module_expansions(deduped)

    logger.info(
        "Deduplication: %s findings -> %s unique findings",
        len(findings),
        len(deduped),
    )
    return deduped


# ---------------------------------------------------------------------------
# Pass 1 – fingerprint
# ---------------------------------------------------------------------------

def _deduplicate_by_fingerprint(findings: list[dict]) -> list[dict]:
    seen: dict[str, dict] = {}
    order: list[str] = []

    for finding in findings:
        fingerprint = finding.get("fingerprint", "")
        if not fingerprint:
            # Use canonical_rule_id for fingerprinting when available
            rule_id = finding.get("canonical_rule_id") or finding.get("rule_id") or ""
            fp = normalize_file_path(finding.get("file_path", ""))
            res = normalize_resource(finding.get("resource")) if finding.get("resource") else ""
            line = finding.get("line_start")
            fingerprint = f"{rule_id}:{fp}:{res}:{line}"
            finding["fingerprint"] = fingerprint

        if fingerprint in seen:
            seen[fingerprint] = _merge_findings(seen[fingerprint], finding)
        else:
            seen[fingerprint] = finding
            order.append(fingerprint)

    return [seen[key] for key in order]


# ---------------------------------------------------------------------------
# Pass 2 – cross-scanner semantic deduplication
# ---------------------------------------------------------------------------

def _deduplicate_cross_scanner(findings: list[dict]) -> list[dict]:
    """Group findings by (file, resource, severity, category) and merge
    those that originate from different scanners."""
    groups: dict[tuple, list[dict]] = defaultdict(list)
    original_order: dict[tuple, int] = {}
    order_idx = 0

    for finding in findings:
        key = _cross_scanner_key(finding)
        groups[key].append(finding)
        if key not in original_order:
            original_order[key] = order_idx
            order_idx += 1

    result: list[dict] = []
    for key in sorted(groups, key=lambda k: original_order[k]):
        group = groups[key]
        if len(group) == 1:
            result.append(group[0])
            continue

        scanners_in_group = {f.get("scanner") for f in group}
        if len(scanners_in_group) <= 1:
            # All from the same scanner – keep all (different rules)
            result.extend(group)
            continue

        # Multiple scanners: merge into one finding
        merged = group[0]
        for other in group[1:]:
            merged = _merge_findings(merged, other)
        result.append(merged)

    return result


def _cross_scanner_key(finding: dict) -> tuple:
    """Return a grouping key for cross-scanner deduplication."""
    fp = normalize_file_path(finding.get("file_path", ""))
    res = normalize_resource(finding.get("resource")) if finding.get("resource") else ""
    sev = (finding.get("severity") or "").upper()
    cat = (finding.get("category") or "").upper()
    return (fp, res, sev, cat)


# ---------------------------------------------------------------------------
# Pass 3 – Terraform module-expansion deduplication
# ---------------------------------------------------------------------------

def _is_module_ref_finding(finding: dict) -> bool:
    """Return True when this finding looks like a module-reference duplicate.

    Pattern: resource contains at least 3 dot-segments where the second-to-last
    segment looks like a Terraform resource type (contains underscore), AND the
    file_path is empty (the merged root-module document carries no path).
    """
    if (finding.get("file_path") or "").strip():
        return False  # has a real file → not a module-ref artifact
    res = finding.get("resource") or ""
    parts = res.split(".")
    return len(parts) >= 3 and "_" in parts[-2]


def _resource_leaf(finding: dict) -> str:
    """Return the final dot-segment of the resource identifier."""
    res = finding.get("resource") or ""
    return res.rsplit(".", 1)[-1] if "." in res else res


def _deduplicate_module_expansions(findings: list[dict]) -> list[dict]:
    """Merge module-ref duplicates with their direct-scan counterparts.

    When a Terraform module directory is scanned both standalone
    (producing findings with real file_paths like ``modules/x/main.tf``)
    and as a root-module reference (producing findings where resource is
    ``module.aws_instance.name`` and file_path is empty), the same
    vulnerability is reported twice.  This pass merges them, keeping the
    direct-scan finding (which has the actual file location).
    """
    module_refs = [f for f in findings if _is_module_ref_finding(f)]
    if not module_refs:
        return findings

    # Index module-ref findings by (canonical_rule_id, resource_leaf)
    ref_index: dict[tuple, list[dict]] = defaultdict(list)
    for f in module_refs:
        rule = f.get("canonical_rule_id") or f.get("rule_id") or ""
        ref_index[(rule, _resource_leaf(f))].append(f)

    consumed: set[int] = set()
    result: list[dict] = []

    for finding in findings:
        if _is_module_ref_finding(finding):
            continue  # will be appended below if unmatched

        rule = finding.get("canonical_rule_id") or finding.get("rule_id") or ""
        key = (rule, _resource_leaf(finding))
        refs = ref_index.get(key, [])

        merged = finding
        for ref in refs:
            rid = id(ref)
            if rid not in consumed:
                # _merge_findings keeps existing's file_path (merged = copy of existing)
                merged = _merge_findings(merged, ref)
                consumed.add(rid)
        result.append(merged)

    # Keep module-ref findings that had no direct-scan counterpart
    for f in module_refs:
        if id(f) not in consumed:
            result.append(f)

    merged_count = len(consumed)
    if merged_count:
        logger.debug("Module-expansion pass merged %s duplicate(s)", merged_count)

    return result


# ---------------------------------------------------------------------------
# Merge helpers
# ---------------------------------------------------------------------------

def _merge_findings(existing: dict, new: dict) -> dict:
    merged = dict(existing)

    for field in RICH_FIELDS:
        existing_val = existing.get(field)
        new_val = new.get(field)
        if _is_richer(new_val, existing_val):
            merged[field] = new_val

    # Merge scanner provenance
    detected = set(existing.get("detected_by") or [])
    if existing.get("scanner"):
        detected.add(existing["scanner"])
    if new.get("scanner"):
        detected.add(new["scanner"])
    for item in new.get("detected_by") or []:
        detected.add(item)
    merged["detected_by"] = sorted(detected)
    merged["scanners"] = merged["detected_by"]

    # Keep the lower line_start (earliest occurrence) when available
    el = existing.get("line_start")
    nl = new.get("line_start")
    if el is None and nl is not None:
        merged["line_start"] = nl
    elif el is not None and nl is not None and nl < el:
        merged["line_start"] = nl

    # Combine rule_ids so the merged finding knows which rules it covers
    rule_ids = set()
    if existing.get("rule_id"):
        rule_ids.add(existing["rule_id"])
    if new.get("rule_id"):
        rule_ids.add(new["rule_id"])
    if len(rule_ids) > 1:
        merged["rule_ids"] = sorted(rule_ids)

    return merged


def _is_richer(new_val: Any, existing_val: Any) -> bool:
    if new_val is None:
        return False
    if existing_val is None:
        return True
    if isinstance(new_val, str) and isinstance(existing_val, str):
        return len(new_val) > len(existing_val)
    if isinstance(new_val, list) and isinstance(existing_val, list):
        return len(new_val) > len(existing_val)
    return False
