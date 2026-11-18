"""Compliance framework mappings for findings enrichment.

Provides category-level AND rule-level mappings across SOC2, HIPAA, PCI DSS,
NIST 800-53, ISO 27001, GDPR, FedRAMP, HITRUST, and CIS benchmarks.
"""

from __future__ import annotations

from pathlib import Path

CATEGORY_FRAMEWORKS: dict[str, list[dict[str, str]]] = {
    "ACCESS_CONTROL": [
        {"framework": "SOC2", "control": "CC6.1", "description": "Logical and physical access controls"},
        {"framework": "PCI_DSS", "control": "7.1", "description": "Limit access to system components"},
        {"framework": "NIST", "control": "AC-3", "description": "Access Enforcement"},
        {"framework": "ISO27001", "control": "A.9.1", "description": "Access control policy"},
        {"framework": "HIPAA", "control": "164.312(a)(1)", "description": "Access control"},
        {"framework": "GDPR", "control": "Art.32", "description": "Security of processing"},
        {"framework": "FedRAMP", "control": "AC-3", "description": "Access Enforcement"},
        {"framework": "HITRUST", "control": "09.a", "description": "Access Control Policy"},
        {"framework": "OWASP_TOP_10", "control": "A01:2021", "description": "Broken Access Control"},
    ],
    "ENCRYPTION": [
        {"framework": "HIPAA", "control": "164.312(a)(2)(iv)", "description": "Encryption and decryption"},
        {"framework": "PCI_DSS", "control": "3.4", "description": "Render PAN unreadable"},
        {"framework": "NIST", "control": "SC-28", "description": "Protection of Information at Rest"},
        {"framework": "SOC2", "control": "CC6.7", "description": "Restriction on information transmission"},
        {"framework": "ISO27001", "control": "A.10.1", "description": "Cryptographic controls"},
        {"framework": "GDPR", "control": "Art.32", "description": "Security of processing"},
        {"framework": "FedRAMP", "control": "SC-28", "description": "Protection of Information at Rest"},
        {"framework": "HITRUST", "control": "09.n", "description": "Encryption of Information"},
        {"framework": "OWASP_TOP_10", "control": "A02:2021", "description": "Cryptographic Failures"},
    ],
    "ENCRYPTION_AT_REST": [
        {"framework": "HIPAA", "control": "164.312(a)(2)(iv)", "description": "Encryption and decryption"},
        {"framework": "PCI_DSS", "control": "3.4", "description": "Render PAN unreadable"},
        {"framework": "NIST", "control": "SC-28", "description": "Protection of Information at Rest"},
        {"framework": "SOC2", "control": "CC6.7", "description": "Restriction on information transmission"},
        {"framework": "ISO27001", "control": "A.10.1", "description": "Cryptographic controls"},
        {"framework": "GDPR", "control": "Art.32", "description": "Security of processing"},
        {"framework": "OWASP_TOP_10", "control": "A02:2021", "description": "Cryptographic Failures"},
    ],
    "ENCRYPTION_IN_TRANSIT": [
        {"framework": "PCI_DSS", "control": "4.1", "description": "Protect cardholder data with strong cryptography"},
        {"framework": "NIST", "control": "SC-8", "description": "Transmission Confidentiality and Integrity"},
        {"framework": "HIPAA", "control": "164.312(e)(2)(ii)", "description": "Encryption and decryption"},
        {"framework": "SOC2", "control": "CC6.7", "description": "Restriction on information transmission"},
        {"framework": "ISO27001", "control": "A.10.1", "description": "Cryptographic controls"},
        {"framework": "GDPR", "control": "Art.32", "description": "Security of processing"},
        {"framework": "OWASP_TOP_10", "control": "A02:2021", "description": "Cryptographic Failures"},
    ],
    "NETWORK": [
        {"framework": "PCI_DSS", "control": "1.3", "description": "Network access control"},
        {"framework": "NIST", "control": "SC-7", "description": "Boundary Protection"},
        {"framework": "SOC2", "control": "CC6.6", "description": "System boundaries"},
        {"framework": "CIS_AWS", "control": "5.2", "description": "Security groups restrict traffic"},
        {"framework": "ISO27001", "control": "A.13.1", "description": "Network security management"},
        {"framework": "HIPAA", "control": "164.312(e)(1)", "description": "Transmission security"},
        {"framework": "OWASP_TOP_10", "control": "A05:2021", "description": "Security Misconfiguration"},
    ],
    "NETWORK_SECURITY": [
        {"framework": "PCI_DSS", "control": "1.3", "description": "Network access control"},
        {"framework": "NIST", "control": "SC-7", "description": "Boundary Protection"},
        {"framework": "SOC2", "control": "CC6.6", "description": "System boundaries"},
        {"framework": "CIS_AWS", "control": "5.2", "description": "Security groups restrict traffic"},
        {"framework": "ISO27001", "control": "A.13.1", "description": "Network security management"},
        {"framework": "HIPAA", "control": "164.312(e)(1)", "description": "Transmission security"},
        {"framework": "OWASP_TOP_10", "control": "A05:2021", "description": "Security Misconfiguration"},
    ],
    "LOGGING": [
        {"framework": "SOC2", "control": "CC7.2", "description": "Monitoring infrastructure"},
        {"framework": "PCI_DSS", "control": "10.2", "description": "Audit trails"},
        {"framework": "NIST", "control": "AU-2", "description": "Audit Events"},
        {"framework": "HIPAA", "control": "164.312(b)", "description": "Audit controls"},
        {"framework": "ISO27001", "control": "A.12.4", "description": "Logging and monitoring"},
        {"framework": "GDPR", "control": "Art.30", "description": "Records of processing activities"},
        {"framework": "OWASP_TOP_10", "control": "A09:2021", "description": "Security Logging and Monitoring Failures"},
    ],
    "AUDIT_LOGGING": [
        {"framework": "SOC2", "control": "CC7.2", "description": "Monitoring infrastructure"},
        {"framework": "PCI_DSS", "control": "10.2", "description": "Audit trails"},
        {"framework": "NIST", "control": "AU-2", "description": "Audit Events"},
        {"framework": "HIPAA", "control": "164.312(b)", "description": "Audit controls"},
        {"framework": "ISO27001", "control": "A.12.4", "description": "Logging and monitoring"},
        {"framework": "GDPR", "control": "Art.30", "description": "Records of processing activities"},
        {"framework": "OWASP_TOP_10", "control": "A09:2021", "description": "Security Logging and Monitoring Failures"},
    ],
    "SECRETS": [
        {"framework": "SOC2", "control": "CC6.1", "description": "Logical and physical access controls"},
        {"framework": "PCI_DSS", "control": "3.5", "description": "Protection of stored cardholder data"},
        {"framework": "NIST", "control": "IA-5", "description": "Authenticator Management"},
        {"framework": "ISO27001", "control": "A.9.4", "description": "Access to source code"},
        {"framework": "HIPAA", "control": "164.312(a)(2)(iv)", "description": "Encryption and decryption"},
        {"framework": "GDPR", "control": "Art.32", "description": "Security of processing"},
        {"framework": "OWASP_TOP_10", "control": "A07:2021", "description": "Identification and Authentication Failures"},
    ],
    "SECRETS_MANAGEMENT": [
        {"framework": "SOC2", "control": "CC6.1", "description": "Logical and physical access controls"},
        {"framework": "PCI_DSS", "control": "3.5", "description": "Protection of stored cardholder data"},
        {"framework": "NIST", "control": "IA-5", "description": "Authenticator Management"},
        {"framework": "ISO27001", "control": "A.9.4", "description": "Access to source code"},
        {"framework": "GDPR", "control": "Art.32", "description": "Security of processing"},
        {"framework": "OWASP_TOP_10", "control": "A07:2021", "description": "Identification and Authentication Failures"},
    ],
    "IAM": [
        {"framework": "SOC2", "control": "CC6.2", "description": "Prior to issuing system credentials"},
        {"framework": "PCI_DSS", "control": "7.2", "description": "Establish an access control system"},
        {"framework": "NIST", "control": "AC-6", "description": "Least Privilege"},
        {"framework": "HIPAA", "control": "164.312(a)(1)", "description": "Access control"},
        {"framework": "ISO27001", "control": "A.9.2", "description": "User access management"},
        {"framework": "GDPR", "control": "Art.25", "description": "Data protection by design"},
        {"framework": "OWASP_TOP_10", "control": "A01:2021", "description": "Broken Access Control"},
    ],
    "CONTAINER_SECURITY": [
        {"framework": "CIS_DOCKER", "control": "4.1", "description": "Ensure a user for the container"},
        {"framework": "CIS_KUBERNETES", "control": "5.2", "description": "Minimize the admission of privileged containers"},
        {"framework": "NIST", "control": "CM-6", "description": "Configuration Settings"},
        {"framework": "SOC2", "control": "CC6.6", "description": "System boundaries"},
        {"framework": "PCI_DSS", "control": "2.2", "description": "Develop configuration standards"},
        {"framework": "ISO27001", "control": "A.12.6", "description": "Technical vulnerability management"},
        {"framework": "OWASP_TOP_10", "control": "A05:2021", "description": "Security Misconfiguration"},
    ],
    "SUPPLY_CHAIN": [
        {"framework": "NIST", "control": "SR-3", "description": "Supply Chain Controls and Processes"},
        {"framework": "ISO27001", "control": "A.15.1", "description": "Information security in supplier relationships"},
        {"framework": "PCI_DSS", "control": "12.8", "description": "Manage service providers"},
        {"framework": "OWASP_TOP_10", "control": "A08:2021", "description": "Software and Data Integrity Failures"},
    ],
    "SECURE_DEFAULTS": [
        {"framework": "NIST", "control": "CM-6", "description": "Configuration Settings"},
        {"framework": "SOC2", "control": "CC6.6", "description": "System boundaries"},
        {"framework": "ISO27001", "control": "A.12.6", "description": "Technical vulnerability management"},
        {"framework": "OWASP_TOP_10", "control": "A05:2021", "description": "Security Misconfiguration"},
    ],
    "STORAGE": [
        {"framework": "SOC2", "control": "CC6.7", "description": "Restriction on information transmission"},
        {"framework": "PCI_DSS", "control": "3.4", "description": "Render PAN unreadable"},
        {"framework": "NIST", "control": "SC-28", "description": "Protection of Information at Rest"},
        {"framework": "ISO27001", "control": "A.10.1", "description": "Cryptographic controls"},
        {"framework": "OWASP_TOP_10", "control": "A05:2021", "description": "Security Misconfiguration"},
    ],
    "BACKUP": [
        {"framework": "SOC2", "control": "A1.2", "description": "Environmental protections"},
        {"framework": "NIST", "control": "CP-9", "description": "System Backup"},
        {"framework": "ISO27001", "control": "A.12.3", "description": "Information backup"},
        {"framework": "HIPAA", "control": "164.308(a)(7)", "description": "Contingency plan"},
        {"framework": "PCI_DSS", "control": "9.5", "description": "Protect physical media"},
        {"framework": "OWASP_TOP_10", "control": "A04:2021", "description": "Insecure Design"},
    ],
    "SECURITY": [
        {"framework": "SOC2", "control": "CC6.1", "description": "Logical and physical access controls"},
        {"framework": "NIST", "control": "RA-5", "description": "Vulnerability Monitoring and Scanning"},
        {"framework": "ISO27001", "control": "A.12.6", "description": "Technical vulnerability management"},
        {"framework": "PCI_DSS", "control": "11.2", "description": "Internal and external vulnerability scanning"},
        {"framework": "OWASP_TOP_10", "control": "A06:2021", "description": "Vulnerable and Outdated Components"},
    ],
}

_RULE_COMPLIANCE_CACHE: dict[str, list[dict[str, str]]] = {}


def _load_rule_compliance() -> dict[str, list[dict[str, str]]]:
    if _RULE_COMPLIANCE_CACHE:
        return _RULE_COMPLIANCE_CACHE
    # queries_pack lives at iac_app/queries_pack/ — two levels up from scanner/compliance/
    queries_dir = Path(__file__).resolve().parents[2] / "queries_pack"
    if not queries_dir.exists():
        return _RULE_COMPLIANCE_CACHE
    for metadata_path in queries_dir.rglob("metadata.yaml"):
        try:
            content = metadata_path.read_text(encoding="utf-8", errors="ignore")
            rule_id = ""
            compliance: list[dict[str, str]] = []
            current_framework = ""
            current_control = ""
            in_compliance = False
            for line in content.splitlines():
                stripped = line.strip()
                if stripped.startswith("id:"):
                    rule_id = stripped.split(":", 1)[1].strip().strip('"')
                if stripped == "compliance:":
                    in_compliance = True
                    continue
                if in_compliance:
                    if stripped.startswith("- framework:"):
                        current_framework = stripped.split(":", 1)[1].strip()
                    elif stripped.startswith("control:"):
                        current_control = stripped.split(":", 1)[1].strip().strip('"')
                        if current_framework and current_control:
                            compliance.append({
                                "framework": current_framework,
                                "control": current_control,
                            })
                    elif not stripped.startswith("-") and not stripped.startswith("control:") and stripped:
                        in_compliance = False
            if rule_id and compliance:
                _RULE_COMPLIANCE_CACHE[rule_id] = compliance
        except Exception:
            continue
    return _RULE_COMPLIANCE_CACHE


def enrich_compliance(finding: dict) -> list[dict[str, str]]:
    """Enrich a finding with compliance framework mappings.

    Uses rule-level mappings from metadata.yaml first, then category-level fallback.
    """
    existing = list(finding.get("compliance") or [])
    seen = {(item.get("framework"), item.get("control")) for item in existing if isinstance(item, dict)}
    rule_id = finding.get("rule_id", "")
    if rule_id:
        rule_compliance = _load_rule_compliance()
        for extra in rule_compliance.get(rule_id, []):
            key = (extra["framework"], extra["control"])
            if key not in seen:
                existing.append(extra)
                seen.add(key)
    category = str(finding.get("category") or "").upper()
    for extra in CATEGORY_FRAMEWORKS.get(category, []):
        key = (extra["framework"], extra["control"])
        if key not in seen:
            existing.append(extra)
            seen.add(key)
    return existing


FRAMEWORK_DESCRIPTIONS = {
    "CIS_AWS": "Center for Internet Security - AWS Foundations Benchmark",
    "CIS_DOCKER": "Center for Internet Security - Docker Benchmark",
    "CIS_GITHUB": "Center for Internet Security - GitHub Actions Benchmark",
    "CIS_KUBERNETES": "Center for Internet Security - Kubernetes Benchmark",
    "SOC2": "Service Organization Control 2 (AICPA Trust Services Criteria)",
    "HIPAA": "Health Insurance Portability and Accountability Act",
    "PCI_DSS": "Payment Card Industry Data Security Standard",
    "NIST": "NIST Special Publication 800-53 (Security and Privacy Controls)",
    "ISO27001": "ISO/IEC 27001:2022 (Information Security Management)",
    "GDPR": "General Data Protection Regulation (EU)",
    "FedRAMP": "Federal Risk and Authorization Management Program",
    "HITRUST": "Health Information Trust Alliance (CSF v11)",
    "OWASP_TOP_10": "OWASP Top 10 Web Application Security Risks (2021)",
}


def get_framework_description(framework: str) -> str:
    return FRAMEWORK_DESCRIPTIONS.get(framework, framework)


def get_all_frameworks() -> list[dict[str, str]]:
    return [
        {"id": fw, "name": desc}
        for fw, desc in FRAMEWORK_DESCRIPTIONS.items()
    ]


def get_rule_compliance(rule_id: str) -> list[dict[str, str]]:
    rule_compliance = _load_rule_compliance()
    return rule_compliance.get(rule_id, [])
