"""Preset reference-source URL catalogs (OWASP, NVD, MITRE, CISA, …)."""

from __future__ import annotations

from app.defaults.nvd_urls import urls_for_mode as nvd_urls_for_mode
from app.defaults.owasp_urls import urls_for_mode as owasp_urls_for_mode

KNOWN_KEYS = ("OWASP", "NVD", "MITRE", "CISA")


MITRE_TOP10: list[str] = [
    "https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html",
    "https://cwe.mitre.org/",
    "https://cwe.mitre.org/data/definitions/79.html",
    "https://cwe.mitre.org/data/definitions/89.html",
    "https://cwe.mitre.org/data/definitions/287.html",
    "https://cwe.mitre.org/data/definitions/352.html",
    "https://cwe.mitre.org/data/definitions/502.html",
    "https://attack.mitre.org/",
    "https://attack.mitre.org/matrices/enterprise/",
    "https://capec.mitre.org/",
]

MITRE_EXTRA: list[str] = [
    "https://cwe.mitre.org/data/definitions/22.html",
    "https://cwe.mitre.org/data/definitions/78.html",
    "https://cwe.mitre.org/data/definitions/434.html",
    "https://cwe.mitre.org/data/definitions/798.html",
    "https://attack.mitre.org/techniques/enterprise/",
]

CISA_TOP10: list[str] = [
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "https://www.cisa.gov/news-events/cybersecurity-advisories",
    "https://www.cisa.gov/topics/cyber-threats-and-advisories",
    "https://www.cisa.gov/topics/cybersecurity-best-practices",
    "https://www.cisa.gov/secure-by-design",
    "https://www.cisa.gov/news-events/alerts",
    "https://www.cisa.gov/resources-tools/resources/binding-operational-directive-22-01",
    "https://www.cisa.gov/news-events/directives",
    "https://www.cisa.gov/stopransomware",
    "https://www.cisa.gov/shields-up",
]

CISA_EXTRA: list[str] = [
    "https://www.cisa.gov/topics/industrial-control-systems",
    "https://www.cisa.gov/topics/partnering-industry",
    "https://www.cisa.gov/resources-tools/services",
    "https://www.cisa.gov/news-events/bulletins",
    "https://www.cisa.gov/vulnerability-disclosure-policy",
]


def urls_for_key(key: str, mode: str) -> list[str]:
    """Return preset URLs for a known source key + mode. Unknown → []."""
    normalized = (key or "").strip().upper()
    if mode == "custom":
        return []
    if normalized == "OWASP":
        return owasp_urls_for_mode(mode)
    if normalized == "NVD":
        return nvd_urls_for_mode(mode)
    if normalized == "MITRE":
        if mode == "top15":
            return list(MITRE_TOP10) + list(MITRE_EXTRA)
        if mode == "top10":
            return list(MITRE_TOP10)
        return []
    if normalized == "CISA":
        if mode == "top15":
            return list(CISA_TOP10) + list(CISA_EXTRA)
        if mode == "top10":
            return list(CISA_TOP10)
        return []
    return []


def default_reference_sources(
    owasp_mode: str = "top10",
    nvd_mode: str = "top10",
    owasp_urls: list[str] | None = None,
    nvd_urls: list[str] | None = None,
) -> list[dict]:
    """Default set when a project is created with no sources."""
    return [
        {
            "key": "OWASP",
            "name": "OWASP",
            "mode": owasp_mode or "top10",
            "urls": list(owasp_urls) if owasp_urls else urls_for_key("OWASP", owasp_mode or "top10"),
        },
        {
            "key": "NVD",
            "name": "NVD",
            "mode": nvd_mode or "top10",
            "urls": list(nvd_urls) if nvd_urls else urls_for_key("NVD", nvd_mode or "top10"),
        },
    ]


def normalize_sources(
    raw: list | None,
    *,
    owasp_mode: str = "top10",
    nvd_mode: str = "top10",
    owasp_urls: list[str] | None = None,
    nvd_urls: list[str] | None = None,
) -> list[dict]:
    """Normalize client-supplied sources; fill empty URL lists from presets."""
    if not raw:
        return default_reference_sources(owasp_mode, nvd_mode, owasp_urls, nvd_urls)

    sources: list[dict] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        key = str(item.get("key") or item.get("name") or "Custom").strip() or "Custom"
        name = str(item.get("name") or key).strip() or key
        mode = str(item.get("mode") or "custom").strip() or "custom"
        urls = item.get("urls") or []
        if not isinstance(urls, list):
            urls = []
        urls = [str(u).strip() for u in urls if str(u).strip()]
        if not urls and mode != "custom":
            urls = urls_for_key(key, mode)
        sources.append({"key": key, "name": name, "mode": mode, "urls": urls})
    return sources or default_reference_sources(owasp_mode, nvd_mode, owasp_urls, nvd_urls)


def sync_legacy_fields(data: dict, sources: list[dict]) -> None:
    """Keep owasp_* / nvd_* columns in sync for older readers."""
    owasp = next((s for s in sources if s["key"].upper() == "OWASP"), None)
    nvd = next((s for s in sources if s["key"].upper() == "NVD"), None)
    if owasp:
        data["owasp_mode"] = owasp.get("mode") or "top10"
        data["owasp_urls"] = list(owasp.get("urls") or [])
    if nvd:
        data["nvd_mode"] = nvd.get("mode") or "top10"
        data["nvd_urls"] = list(nvd.get("urls") or [])
