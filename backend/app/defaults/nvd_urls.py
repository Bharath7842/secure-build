"""Default NVD reference URL sets — Java / JVM ecosystem CVE details."""

from __future__ import annotations


def _nvd_cve(cve_id: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


# Java-related CVE detail pages (Java SE, Spring, Log4j, Tomcat, etc.).
TOP10: list[str] = [
    _nvd_cve("CVE-2026-21945"),  # Oracle Java SE
    _nvd_cve("CVE-2026-34268"),  # Oracle Java SE
    _nvd_cve("CVE-2025-30754"),  # Oracle Java SE (JSSE)
    _nvd_cve("CVE-2026-34478"),  # Apache Log4j
    _nvd_cve("CVE-2026-22737"),  # Spring Framework
    _nvd_cve("CVE-2021-44228"),  # Log4Shell
    _nvd_cve("CVE-2022-22965"),  # Spring4Shell
    _nvd_cve("CVE-2017-5638"),  # Apache Struts RCE
    _nvd_cve("CVE-2024-50379"),  # Apache Tomcat
    _nvd_cve("CVE-2023-24998"),  # Apache Commons FileUpload
]

# Additional well-known Java / JVM CVEs for Top 15.
EXTRA: list[str] = [
    _nvd_cve("CVE-2021-45046"),  # Log4j incomplete fix follow-up
    _nvd_cve("CVE-2022-22963"),  # Spring Cloud Function SpEL RCE
    _nvd_cve("CVE-2023-46604"),  # Apache ActiveMQ RCE
    _nvd_cve("CVE-2024-38816"),  # Spring Framework path traversal
    _nvd_cve("CVE-2025-24813"),  # Apache Tomcat RCE
]

TOP15: list[str] = TOP10 + EXTRA


def urls_for_mode(mode: str) -> list[str]:
    """Return default NVD reference URLs for a given nvd_mode."""
    if mode == "top10":
        return list(TOP10)
    if mode == "top15":
        return list(TOP15)
    return []


def default_nvd_urls() -> list[str]:
    """Backward-compatible alias: default is Top 10."""
    return urls_for_mode("top10")
