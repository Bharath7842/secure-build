"""
Run Checkov's vendored built-in checks against our normalized IaC documents.

Checkov checks are auto-registered into their type-specific registries when
their module is imported. This module imports all check modules once, then
for each registered check wraps our document format into checkov's list-wrapped
conf format and calls scan_resource_conf() directly.
"""
from __future__ import annotations

import importlib
import logging
import pkgutil
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_VENDOR_DIR = str(Path(__file__).resolve().parents[5] / "vendor" / "checkov")
if _VENDOR_DIR not in sys.path:
    sys.path.insert(0, _VENDOR_DIR)


def _to_checkov_conf(attrs: dict) -> dict:
    """Wrap plain attribute values into Checkov's list-wrapped conf format."""
    result = {}
    for key, value in attrs.items():
        if isinstance(value, list):
            result[key] = [
                _to_checkov_conf(item) if isinstance(item, dict) else item
                for item in value
            ]
        elif isinstance(value, dict):
            result[key] = [_to_checkov_conf(value)]
        else:
            result[key] = [value]
    return result


def _import_package(package_name: str) -> None:
    """Recursively import all modules in a package to trigger check registration."""
    try:
        pkg = importlib.import_module(package_name)
    except ImportError as exc:
        logger.debug("Cannot import %s: %s", package_name, exc)
        return
    pkg_path = getattr(pkg, "__path__", None)
    if not pkg_path:
        return
    for _importer, modname, _ispkg in pkgutil.walk_packages(pkg_path, prefix=package_name + "."):
        try:
            importlib.import_module(modname)
        except Exception as exc:
            logger.debug("Skipped %s: %s", modname, exc)


_checks_loaded = False


def _ensure_checks_loaded() -> None:
    global _checks_loaded
    if _checks_loaded:
        return
    _import_package("checkov.terraform.checks.resource.aws")
    _import_package("checkov.terraform.checks.resource.azure")
    _import_package("checkov.terraform.checks.resource.gcp")
    _import_package("checkov.kubernetes.checks.resource.k8s")
    _import_package("checkov.dockerfile.checks")
    _checks_loaded = True


def run_terraform_checks(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Run all registered Checkov Terraform resource checks against a document.

    Returns findings in the same dict format as our native query policies.
    """
    _ensure_checks_loaded()
    try:
        from checkov.terraform.checks.resource.registry import resource_registry as registry
        from checkov.common.models.enums import CheckResult
    except ImportError:
        return []

    findings = []
    for resource in document.get("resources") or []:
        rtype = resource.get("type") or ""
        checks = registry.get_checks(rtype)
        if not checks:
            continue
        attrs = resource.get("attributes") or {}
        conf = _to_checkov_conf(attrs)
        loc = resource.get("location") or {}

        for check in checks:
            try:
                result = check.scan_resource_conf(conf)
                if result == CheckResult.FAILED or result is False:
                    findings.append({
                        "rule_id": check.id if check.id.startswith("CKV") else f"CKV_{check.id}",
                        "title": check.name,
                        "description": check.name,
                        "severity": _checkov_severity(check),
                        "category": _checkov_category(check),
                        "finding_type": "MISCONFIGURATION",
                        "iac_type": "terraform",
                        "provider": _resource_provider(rtype),
                        "resource": resource.get("id"),
                        "resource_type": rtype,
                        "scanner": "checkov",
                        "detected_by": ["checkov"],
                        "file_path": loc.get("file_path", ""),
                        "line_start": loc.get("line_start"),
                        "line_end": loc.get("line_end"),
                        "evidence": "",
                        "remediation": (check.details[0] if getattr(check, "details", None) else ""),
                        "references": [],
                        "compliance": [],
                        "policy_id": check.id,
                        "policy_version": "1.0.0",
                        "cwe": None,
                        "owasp_category": None,
                    })
            except Exception as exc:
                logger.debug("Check %s failed on %s: %s", check.id, resource.get("id"), exc)
    return findings


def _checkov_severity(check: Any) -> str:
    try:
        from checkov.common.models.enums import CheckCategories
        cats = getattr(check, "categories", [])
        high = {CheckCategories.ENCRYPTION, CheckCategories.IAM, CheckCategories.GENERAL_SECURITY}
        if any(c in high for c in cats):
            return "HIGH"
        medium = {CheckCategories.NETWORKING, CheckCategories.LOGGING, CheckCategories.BACKUP_AND_RECOVERY}
        if any(c in medium for c in cats):
            return "MEDIUM"
    except Exception:
        pass
    return "LOW"


def _checkov_category(check: Any) -> str:
    try:
        cats = getattr(check, "categories", [])
        if cats:
            name = str(cats[0])
            if "." in name:
                name = name.split(".")[-1]
            return name
    except Exception:
        pass
    return "SECURITY"


def _resource_provider(resource_type: str) -> str:
    if resource_type.startswith("aws_"):
        return "aws"
    if resource_type.startswith("azurerm_") or resource_type.startswith("azure_"):
        return "azure"
    if resource_type.startswith("google_"):
        return "gcp"
    return ""
