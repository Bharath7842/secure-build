"""Detailed security checks configuration."""

SECURITY_CHECKS = {
    "SECRETS": {
        "name": "Secrets Detection",
        "description": "Detects hardcoded secrets, passwords, API keys, and tokens",
        "checks": [
            {
                "id": "secret-password",
                "name": "Hardcoded Password",
                "description": "Detects hardcoded passwords in configuration files",
                "severity": "CRITICAL",
                "cwe": "CWE-798",
                "owasp": "A07:2021",
            },
            {
                "id": "secret-api-key",
                "name": "Hardcoded API Key",
                "description": "Detects hardcoded API keys",
                "severity": "CRITICAL",
                "cwe": "CWE-798",
                "owasp": "A07:2021",
            },
            {
                "id": "secret-token",
                "name": "Hardcoded Token",
                "description": "Detects hardcoded authentication tokens",
                "severity": "HIGH",
                "cwe": "CWE-798",
                "owasp": "A07:2021",
            },
        ],
    },
    "ENCRYPTION": {
        "name": "Encryption",
        "description": "Checks for missing or weak encryption configurations",
        "checks": [
            {
                "id": "encrypt-s3",
                "name": "S3 Bucket Encryption",
                "description": "S3 buckets should have server-side encryption enabled",
                "severity": "HIGH",
                "cwe": "CWE-311",
                "owasp": "A02:2021",
            },
            {
                "id": "encrypt-ebs",
                "name": "EBS Volume Encryption",
                "description": "EBS volumes should be encrypted",
                "severity": "MEDIUM",
                "cwe": "CWE-311",
                "owasp": "A02:2021",
            },
            {
                "id": "encrypt-rds",
                "name": "RDS Storage Encryption",
                "description": "RDS instances should have storage encryption enabled",
                "severity": "HIGH",
                "cwe": "CWE-311",
                "owasp": "A02:2021",
            },
            {
                "id": "encrypt-tls",
                "name": "TLS Configuration",
                "description": "Services should use TLS for secure communication",
                "severity": "HIGH",
                "cwe": "CWE-326",
                "owasp": "A02:2021",
            },
        ],
    },
    "IAM": {
        "name": "Identity and Access Management",
        "description": "Checks for overly permissive IAM policies",
        "checks": [
            {
                "id": "iam-wildcard",
                "name": "Wildcard Permissions",
                "description": "IAM policies should not use wildcard permissions",
                "severity": "CRITICAL",
                "cwe": "CWE-250",
                "owasp": "A01:2021",
            },
            {
                "id": "iam-admin",
                "name": "Administrator Access",
                "description": "Avoid granting AdministratorAccess policy",
                "severity": "CRITICAL",
                "cwe": "CWE-250",
                "owasp": "A01:2021",
            },
            {
                "id": "iam-privilege-escalation",
                "name": "Privilege Escalation",
                "description": "Check for IAM privilege escalation paths",
                "severity": "HIGH",
                "cwe": "CWE-250",
                "owasp": "A01:2021",
            },
        ],
    },
    "NETWORK": {
        "name": "Network Security",
        "description": "Checks for network security misconfigurations",
        "checks": [
            {
                "id": "net-ssh-open",
                "name": "SSH Open to Internet",
                "description": "SSH should not be open to 0.0.0.0/0",
                "severity": "CRITICAL",
                "cwe": "CWE-284",
                "owasp": "A05:2021",
            },
            {
                "id": "net-rdp-open",
                "name": "RDP Open to Internet",
                "description": "RDP should not be open to 0.0.0.0/0",
                "severity": "CRITICAL",
                "cwe": "CWE-284",
                "owasp": "A05:2021",
            },
            {
                "id": "net-all-ports",
                "name": "All Ports Open",
                "description": "Security groups should not allow all inbound traffic",
                "severity": "HIGH",
                "cwe": "CWE-284",
                "owasp": "A05:2021",
            },
            {
                "id": "net-unrestricted-egress",
                "name": "Unrestricted Egress",
                "description": "Consider restricting outbound traffic",
                "severity": "LOW",
                "cwe": "CWE-284",
                "owasp": "A05:2021",
            },
        ],
    },
    "CONTAINER": {
        "name": "Container Security",
        "description": "Checks for Docker container security issues",
        "checks": [
            {
                "id": "container-root",
                "name": "Running as Root",
                "description": "Containers should not run as root",
                "severity": "HIGH",
                "cwe": "CWE-693",
                "owasp": "A05:2021",
            },
            {
                "id": "container-ssh",
                "name": "SSH Exposed",
                "description": "Containers should not expose SSH port",
                "severity": "HIGH",
                "cwe": "CWE-693",
                "owasp": "A05:2021",
            },
            {
                "id": "container-docker-socket",
                "name": "Docker Socket Mounted",
                "description": "Docker socket should not be mounted",
                "severity": "CRITICAL",
                "cwe": "CWE-693",
                "owasp": "A05:2021",
            },
            {
                "id": "container-healthcheck",
                "name": "Missing Health Check",
                "description": "Containers should have health checks",
                "severity": "MEDIUM",
                "cwe": "CWE-693",
                "owasp": "A05:2021",
            },
        ],
    },
    "KUBERNETES": {
        "name": "Kubernetes Security",
        "description": "Checks for Kubernetes security issues",
        "checks": [
            {
                "id": "k8s-privileged",
                "name": "Privileged Container",
                "description": "Containers should not run in privileged mode",
                "severity": "CRITICAL",
                "cwe": "CWE-693",
                "owasp": "A05:2021",
            },
            {
                "id": "k8s-host-network",
                "name": "Host Network Access",
                "description": "Pods should not use host network",
                "severity": "HIGH",
                "cwe": "CWE-693",
                "owasp": "A05:2021",
            },
            {
                "id": "k8s-resource-limits",
                "name": "Missing Resource Limits",
                "description": "Containers should have resource limits",
                "severity": "MEDIUM",
                "cwe": "CWE-693",
                "owasp": "A05:2021",
            },
            {
                "id": "k8s-root-user",
                "name": "Running as Root",
                "description": "Containers should not run as root",
                "severity": "HIGH",
                "cwe": "CWE-693",
                "owasp": "A05:2021",
            },
            {
                "id": "k8s-privilege-escalation",
                "name": "Privilege Escalation",
                "description": "Containers should not allow privilege escalation",
                "severity": "HIGH",
                "cwe": "CWE-693",
                "owasp": "A05:2021",
            },
        ],
    },
    "STORAGE": {
        "name": "Storage Security",
        "description": "Checks for storage security issues",
        "checks": [
            {
                "id": "storage-s3-public",
                "name": "S3 Public Access",
                "description": "S3 buckets should not be public",
                "severity": "CRITICAL",
                "cwe": "CWE-538",
                "owasp": "A05:2021",
            },
            {
                "id": "storage-s3-versioning",
                "name": "S3 Versioning",
                "description": "S3 buckets should have versioning enabled",
                "severity": "MEDIUM",
                "cwe": "CWE-538",
                "owasp": "A05:2021",
            },
            {
                "id": "storage-s3-public-access-block",
                "name": "S3 Public Access Block",
                "description": "S3 buckets should block public access",
                "severity": "HIGH",
                "cwe": "CWE-538",
                "owasp": "A05:2021",
            },
            {
                "id": "storage-pv-delete",
                "name": "PV Delete Policy",
                "description": "PersistentVolumes should use Retain policy",
                "severity": "MEDIUM",
                "cwe": "CWE-538",
                "owasp": "A05:2021",
            },
        ],
    },
}


def get_security_checks(category: str = None) -> dict:
    """Get security checks, optionally filtered by category."""
    if category:
        return {category: SECURITY_CHECKS.get(category, {})}
    return SECURITY_CHECKS


def get_all_check_ids() -> list[str]:
    """Get all check IDs across all categories."""
    check_ids = []
    for category, config in SECURITY_CHECKS.items():
        for check in config.get("checks", []):
            check_ids.append(check["id"])
    return check_ids


def get_check_by_id(check_id: str) -> dict:
    """Get a specific check by its ID."""
    for category, config in SECURITY_CHECKS.items():
        for check in config.get("checks", []):
            if check["id"] == check_id:
                return {**check, "category": category}
    return None
