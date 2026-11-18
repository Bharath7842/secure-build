"""Canonical enumerations for the IaC security platform."""

from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingType(str, Enum):
    MISCONFIGURATION = "MISCONFIGURATION"
    SECRET = "SECRET"
    SECURITY = "SECURITY"
    COMPLIANCE = "COMPLIANCE"
    BEST_PRACTICE = "BEST_PRACTICE"
    RELIABILITY = "RELIABILITY"


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class ScanStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    COMPLETED_WITH_ERRORS = "COMPLETED_WITH_ERRORS"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class PolicyLifecycle(str, Enum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    DEPRECATED = "DEPRECATED"


class PolicyEngine(str, Enum):
    INTERNAL = "internal"
    OPA = "opa"
    TRIVY = "trivy"
    KICS = "kics"


class IacType(str, Enum):
    TERRAFORM = "terraform"
    KUBERNETES = "kubernetes"
    DOCKER = "docker"
    CLOUDFORMATION = "cloudformation"
    HELM = "helm"
    ANSIBLE = "ansible"
    BICEP = "bicep"
    ARM = "arm"
    PULUMI = "pulumi"
    GITHUB_ACTIONS = "github_actions"
    UNKNOWN = "unknown"


class Role(str, Enum):
    ADMIN = "ADMIN"
    SECURITY_ENGINEER = "SECURITY_ENGINEER"
    DEVELOPER = "DEVELOPER"
    VIEWER = "VIEWER"


SEVERITY_RANK = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


def normalize_severity(value: str | None) -> str:
    if not value:
        return Severity.INFO.value
    key = str(value).strip().upper()
    aliases = {
        "ERROR": Severity.HIGH.value,
        "WARN": Severity.MEDIUM.value,
        "WARNING": Severity.MEDIUM.value,
        "NOTE": Severity.INFO.value,
        "INFORMATIONAL": Severity.INFO.value,
        "UNKNOWN": Severity.INFO.value,
    }
    if key in aliases:
        return aliases[key]
    try:
        return Severity(key).value
    except ValueError:
        return Severity.INFO.value
