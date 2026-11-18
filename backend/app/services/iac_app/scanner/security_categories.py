"""Security categories configuration for IaC scanning."""

SECURITY_CATEGORIES = {
    "SECURITY_MISCONFIGURATION": {
        "name": "Security Misconfigurations",
        "description": "General security misconfigurations in infrastructure code",
        "severity_weight": 1.0,
    },
    "SECRETS": {
        "name": "Secrets",
        "description": "Hardcoded secrets, passwords, API keys, and tokens",
        "severity_weight": 1.5,
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "cwe": "CWE-798",
    },
    "ENCRYPTION": {
        "name": "Encryption",
        "description": "Missing or weak encryption configurations",
        "severity_weight": 1.2,
        "owasp": "A02:2021 - Cryptographic Failures",
        "cwe": "CWE-311",
    },
    "IAM": {
        "name": "IAM",
        "description": "Identity and Access Management issues",
        "severity_weight": 1.3,
        "owasp": "A01:2021 - Broken Access Control",
        "cwe": "CWE-250",
    },
    "NETWORK": {
        "name": "Network Security",
        "description": "Network security misconfigurations",
        "severity_weight": 1.1,
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-284",
    },
    "CONTAINER": {
        "name": "Container Security",
        "description": "Docker and container image security issues",
        "severity_weight": 1.2,
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-693",
    },
    "KUBERNETES": {
        "name": "Kubernetes Security",
        "description": "Kubernetes configuration security issues",
        "severity_weight": 1.2,
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-693",
    },
    "STORAGE": {
        "name": "Storage Security",
        "description": "Cloud storage security misconfigurations",
        "severity_weight": 1.1,
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-538",
    },
    "DATABASE": {
        "name": "Database Security",
        "description": "Database security misconfigurations",
        "severity_weight": 1.2,
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-538",
    },
    "COMPUTE": {
        "name": "Compute Security",
        "description": "Compute resource security issues",
        "severity_weight": 1.0,
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-693",
    },
    "CDN": {
        "name": "CDN Security",
        "description": "CDN and edge security issues",
        "severity_weight": 0.9,
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-693",
    },
}

SEVERITY_WEIGHTS = {
    "CRITICAL": 4.0,
    "HIGH": 3.0,
    "MEDIUM": 2.0,
    "LOW": 1.0,
    "UNKNOWN": 0.5,
}


def get_category_info(category: str) -> dict:
    """Get information about a security category."""
    return SECURITY_CATEGORIES.get(category, {
        "name": category,
        "description": "Other security issues",
        "severity_weight": 1.0,
    })


# DEPRECATED: Use risk_engine.calculate_risk() instead, which now uses
# the weighted scoring logic below and returns full scan statistics.
def calculate_risk_score(findings: list) -> float:
    """Calculate overall risk score based on findings."""
    if not findings:
        return 0.0

    total_score = 0.0
    for finding in findings:
        severity = finding.get("severity", "UNKNOWN")
        category = finding.get("category", "SECURITY_MISCONFIGURATION")

        severity_weight = SEVERITY_WEIGHTS.get(severity, 0.5)
        category_info = get_category_info(category)
        category_weight = category_info.get("severity_weight", 1.0)

        total_score += severity_weight * category_weight

    max_possible = len(findings) * 4.0 * 1.5
    if max_possible > 0:
        normalized_score = (total_score / max_possible) * 100
        return min(round(normalized_score, 2), 100.0)

    return 0.0
