"""Stub: cloudsplaining-based IAM checks are skipped (cloudsplaining not vendored)."""
from __future__ import annotations
from typing import Dict, List, Any
from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class BaseTerraformCloudsplainingResourceIAMCheck(BaseResourceCheck):
    def __init__(self, name: str, id: str) -> None:
        supported_resources: tuple = ()  # Empty: won't register for any resource
        super().__init__(name=name, id=id, categories=(CheckCategories.IAM,), supported_resources=supported_resources)

    def scan_resource_conf(self, conf: Dict[str, List[Any]]) -> CheckResult:
        return CheckResult.UNKNOWN
