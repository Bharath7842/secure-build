"""PCI, ISO 27001 and SOC 2 views over the check catalog's existing standards tags.

This is a report. It does not decide what a scan runs.
"""

from __future__ import annotations

from app.services.dast_catalog import default_catalog

# Each requirement names the OWASP tags (or a check-id prefix) that satisfy it.
_FRAMEWORKS: dict[str, dict] = {
    "pci": {
        "name": "PCI DSS",
        "requirements": [
            {"id": "6.2.4", "name": "Injection flaws", "owasp": ["A03:2021"]},
            {"id": "6.2.4-access", "name": "Broken access control", "owasp": ["A01:2021"]},
            {"id": "8.3", "name": "Authentication", "owasp": ["A07:2021"]},
            {"id": "4.2", "name": "Strong cryptography in transit", "prefix": "dast-tls"},
            {"id": "6.2.4-xss", "name": "Cross-site scripting", "owasp": ["A03:2021"], "cwe": ["CWE-79"]},
        ],
    },
    "iso": {
        "name": "ISO/IEC 27001",
        "requirements": [
            {"id": "A.8.5", "name": "Secure authentication", "owasp": ["A07:2021"]},
            {"id": "A.8.3", "name": "Access restriction", "owasp": ["A01:2021"]},
            {"id": "A.8.24", "name": "Use of cryptography", "prefix": "dast-tls"},
            {"id": "A.8.8", "name": "Technical vulnerabilities", "owasp": ["A03:2021", "A05:2021"]},
        ],
    },
    "soc2": {
        "name": "SOC 2",
        "requirements": [
            {"id": "CC6.1", "name": "Logical access", "owasp": ["A01:2021", "A07:2021"]},
            {"id": "CC6.6", "name": "Boundary protection", "owasp": ["A05:2021"], "prefix": "dast-tls"},
            {"id": "CC7.1", "name": "Detection of changes and vulnerabilities", "owasp": ["A03:2021", "A05:2021"]},
        ],
    },
}


def _matches(check, requirement: dict) -> bool:
    standards = check.standards or {}
    wanted_owasp = set(requirement.get("owasp") or [])
    wanted_cwe = set(requirement.get("cwe") or [])
    prefix = requirement.get("prefix")
    if prefix and str(check.check_id).startswith(prefix):
        return True
    if wanted_cwe and wanted_cwe.intersection(standards.get("cwe") or []):
        return True
    if wanted_owasp and not wanted_cwe and wanted_owasp.intersection(standards.get("owasp") or []):
        return True
    return False


def compliance_view() -> dict:
    checks = list(default_catalog().checks)
    frameworks = []
    for key, spec in _FRAMEWORKS.items():
        requirements = []
        for requirement in spec["requirements"]:
            matched = [c for c in checks if _matches(c, requirement)]
            requirements.append(
                {
                    "id": requirement["id"],
                    "name": requirement["name"],
                    "check_ids": [c.check_id for c in matched],
                    "covered": bool(matched),
                }
            )
        frameworks.append(
            {
                "id": key,
                "name": spec["name"],
                "requirements": requirements,
                "covered": sum(1 for r in requirements if r["covered"]),
                "total": len(requirements),
            }
        )
    return {"frameworks": frameworks}
