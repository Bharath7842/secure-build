"""Risk engine.

Severity is an input, not the overall risk. Scoring is configurable and
considers exposure, privilege, sensitivity, and compliance impact.
"""

from __future__ import annotations

import logging
from typing import Any

from app.services.iac_app.scanner.security_categories import (
    SECURITY_CATEGORIES,
    SEVERITY_WEIGHTS,
    get_category_info,
)

logger = logging.getLogger(__name__)

DEFAULT_CONFIG = {
    "severity_weights": {
        "CRITICAL": 40,
        "HIGH": 25,
        "MEDIUM": 12,
        "LOW": 5,
        "INFO": 1,
    },
    "factor_weights": {
        "internet_exposed": 20,
        "administrative_privilege": 18,
        "sensitive_resource": 12,
        "secret": 20,
        "compliance_impact": 10,
        "unencrypted": 8,
    },
}


INTERNET_HINTS = ("0.0.0.0/0", "::/0", "public", "public-read", "internet", "open ssh")
ADMIN_HINTS = ("*", "administrator", "privileged", "root", "wildcard")
SENSITIVE_HINTS = ("s3", "rds", "kms", "secret", "password", "iam", "database")


def calculate_risk(findings: list[dict], config: dict[str, Any] | None = None) -> dict:
    cfg = {**DEFAULT_CONFIG, **(config or {})}
    severity_weights = {**DEFAULT_CONFIG["severity_weights"], **cfg.get("severity_weights", {})}
    factor_weights = {**DEFAULT_CONFIG["factor_weights"], **cfg.get("factor_weights", {})}

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "UNKNOWN": 0}
    category_counts: dict[str, int] = {category: 0 for category in SECURITY_CATEGORIES}
    total_weighted = 0.0

    for finding in findings:
        severity = finding.get("severity", "INFO")
        category = finding.get("category", "SECURITY_MISCONFIGURATION")
        factors = _risk_factors(finding)
        finding["risk_factors"] = factors
        score = severity_weights.get(severity, 1)
        for factor in factors:
            key = factor.lower().replace(" ", "_")
            score += factor_weights.get(key, 5)
        score = min(score, 100)
        finding["risk_score"] = score
        finding["risk_level"] = _level_from_score(score)

        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            severity_counts["INFO"] += 1

        category_counts[category] = category_counts.get(category, 0) + 1
        severity_weight = SEVERITY_WEIGHTS.get(severity, 0.5)
        category_info = get_category_info(category)
        category_weight = category_info.get("severity_weight", 1.0)
        total_weighted += severity_weight * category_weight + (len(factors) * 0.4)

    max_possible = max(len(findings) * 4.0 * 1.5, 1)
    risk_score = min(round((total_weighted / max_possible) * 100, 2), 100.0) if findings else 0.0
    risk_level = _level_from_score(risk_score)

    scan_statistics = {
        "total_findings": len(findings),
        "critical_count": severity_counts["CRITICAL"],
        "high_count": severity_counts["HIGH"],
        "medium_count": severity_counts["MEDIUM"],
        "low_count": severity_counts["LOW"],
        "info_count": severity_counts.get("INFO", 0),
        "unknown_count": severity_counts.get("UNKNOWN", 0),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "category_counts": category_counts,
        "categories_scanned": list(SECURITY_CATEGORIES.keys()),
        "internet_exposed": sum(1 for f in findings if "Internet exposed" in (f.get("risk_factors") or [])),
        "secret_findings": sum(1 for f in findings if (f.get("finding_type") or "") == "SECRET"),
    }
    logger.info("Risk calculation: %s", scan_statistics)
    return scan_statistics


def _risk_factors(finding: dict) -> list[str]:
    haystack = " ".join(
        [
            str(finding.get("title") or ""),
            str(finding.get("description") or ""),
            str(finding.get("evidence") or ""),
            str(finding.get("resource") or ""),
            str(finding.get("rule_id") or ""),
        ]
    ).lower()
    factors = []
    if any(hint in haystack for hint in INTERNET_HINTS):
        factors.append("Internet exposed")
    if any(hint in haystack for hint in ADMIN_HINTS):
        factors.append("Administrative privilege")
    if any(hint in haystack for hint in SENSITIVE_HINTS):
        factors.append("Sensitive resource")
    if finding.get("finding_type") == "SECRET" or "secret" in haystack:
        factors.append("Secret")
    if finding.get("compliance"):
        factors.append("Compliance impact")
    if "encrypt" in haystack or "unencrypted" in haystack:
        factors.append("Unencrypted")
    return factors


def _level_from_score(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    if score >= 15:
        return "LOW"
    return "INFO"
