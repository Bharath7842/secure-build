"""owasp_map.py — CWE -> OWASP Top 10:2021 category, for prompt/report labeling.

Not gating: this is vocabulary for the LLM prompt and finding display, not a
detection mechanism. Falls back to a rule's coarse `category` bucket
(secrets/dependency/code) when the CWE has no direct Top 10:2021 mapping, and
finally to UNKNOWN_OWASP when neither is available.
"""

from __future__ import annotations

from typing import Optional

# Best-effort CWE -> OWASP Top 10:2021 mapping, seeded from OWASP's published
# CWE-to-category crosswalk plus every CWE currently used in the rules/ catalog /
# ast_rules.json. Not exhaustive — unmapped CWEs fall back to CATEGORY_FALLBACK.
CWE_TO_OWASP: dict[str, str] = {
    # A01:2021 - Broken Access Control
    "CWE-22": "A01:2021-Broken-Access-Control",
    "CWE-284": "A01:2021-Broken-Access-Control",
    "CWE-352": "A01:2021-Broken-Access-Control",
    "CWE-601": "A01:2021-Broken-Access-Control",
    "CWE-862": "A01:2021-Broken-Access-Control",
    "CWE-863": "A01:2021-Broken-Access-Control",
    # A02:2021 - Cryptographic Failures
    "CWE-259": "A02:2021-Cryptographic-Failures",
    "CWE-295": "A02:2021-Cryptographic-Failures",
    "CWE-326": "A02:2021-Cryptographic-Failures",
    "CWE-327": "A02:2021-Cryptographic-Failures",
    "CWE-328": "A02:2021-Cryptographic-Failures",
    "CWE-330": "A02:2021-Cryptographic-Failures",
    # A03:2021 - Injection
    "CWE-78": "A03:2021-Injection",
    "CWE-79": "A03:2021-Injection",
    "CWE-89": "A03:2021-Injection",
    "CWE-90": "A03:2021-Injection",
    "CWE-91": "A03:2021-Injection",
    "CWE-93": "A03:2021-Injection",
    "CWE-94": "A03:2021-Injection",
    "CWE-113": "A03:2021-Injection",
    "CWE-470": "A03:2021-Injection",
    "CWE-943": "A03:2021-Injection",
    # A04:2021 - Insecure Design
    "CWE-185": "A04:2021-Insecure-Design",
    "CWE-209": "A04:2021-Insecure-Design",
    "CWE-213": "A04:2021-Insecure-Design",
    "CWE-561": "A04:2021-Insecure-Design",
    "CWE-1173": "A04:2021-Insecure-Design",
    # A05:2021 - Security Misconfiguration
    "CWE-16": "A05:2021-Security-Misconfiguration",
    "CWE-489": "A05:2021-Security-Misconfiguration",
    "CWE-611": "A05:2021-Security-Misconfiguration",
    "CWE-614": "A05:2021-Security-Misconfiguration",
    "CWE-693": "A05:2021-Security-Misconfiguration",
    "CWE-942": "A05:2021-Security-Misconfiguration",
    "CWE-1021": "A05:2021-Security-Misconfiguration",
    # A06:2021 - Vulnerable and Outdated Components
    "CWE-937": "A06:2021-Vulnerable-and-Outdated-Components",
    "CWE-1035": "A06:2021-Vulnerable-and-Outdated-Components",
    "CWE-1104": "A06:2021-Vulnerable-and-Outdated-Components",
    # A07:2021 - Identification and Authentication Failures
    "CWE-203": "A07:2021-Identification-and-Authentication-Failures",
    "CWE-255": "A07:2021-Identification-and-Authentication-Failures",
    "CWE-287": "A07:2021-Identification-and-Authentication-Failures",
    "CWE-288": "A07:2021-Identification-and-Authentication-Failures",
    "CWE-290": "A07:2021-Identification-and-Authentication-Failures",
    "CWE-294": "A07:2021-Identification-and-Authentication-Failures",
    "CWE-297": "A07:2021-Identification-and-Authentication-Failures",
    "CWE-306": "A07:2021-Identification-and-Authentication-Failures",
    "CWE-307": "A07:2021-Identification-and-Authentication-Failures",
    "CWE-346": "A07:2021-Identification-and-Authentication-Failures",
    "CWE-347": "A07:2021-Identification-and-Authentication-Failures",
    "CWE-384": "A07:2021-Identification-and-Authentication-Failures",
    "CWE-522": "A07:2021-Identification-and-Authentication-Failures",
    "CWE-620": "A07:2021-Identification-and-Authentication-Failures",
    "CWE-640": "A07:2021-Identification-and-Authentication-Failures",
    "CWE-798": "A07:2021-Identification-and-Authentication-Failures",
    "CWE-940": "A07:2021-Identification-and-Authentication-Failures",
    # A08:2021 - Software and Data Integrity Failures
    "CWE-345": "A08:2021-Software-and-Data-Integrity-Failures",
    "CWE-353": "A08:2021-Software-and-Data-Integrity-Failures",
    "CWE-426": "A08:2021-Software-and-Data-Integrity-Failures",
    "CWE-494": "A08:2021-Software-and-Data-Integrity-Failures",
    "CWE-502": "A08:2021-Software-and-Data-Integrity-Failures",
    "CWE-565": "A08:2021-Software-and-Data-Integrity-Failures",
    "CWE-829": "A08:2021-Software-and-Data-Integrity-Failures",
    "CWE-830": "A08:2021-Software-and-Data-Integrity-Failures",
    # A09:2021 - Security Logging and Monitoring Failures
    "CWE-117": "A09:2021-Security-Logging-and-Monitoring-Failures",
    "CWE-223": "A09:2021-Security-Logging-and-Monitoring-Failures",
    "CWE-532": "A09:2021-Security-Logging-and-Monitoring-Failures",
    "CWE-778": "A09:2021-Security-Logging-and-Monitoring-Failures",
    # A10:2021 - Server-Side Request Forgery
    "CWE-918": "A10:2021-Server-Side-Request-Forgery",
}

# category (the rule catalog's coarse bucket) -> OWASP fallback, used only
# when the rule's cwe is blank or has no entry above.
CATEGORY_FALLBACK: dict[str, str] = {
    "secrets": "A07:2021-Identification-and-Authentication-Failures",
    "dependency": "A06:2021-Vulnerable-and-Outdated-Components",
    "code": "A04:2021-Insecure-Design",
}

UNKNOWN_OWASP = "A04:2021-Insecure-Design"

# Short label list handed to the LLM prompt as the fixed OWASP vocabulary —
# order matches the official Top 10:2021 ranking.
OWASP_TOP_10_2021 = [
    "A01:2021-Broken-Access-Control",
    "A02:2021-Cryptographic-Failures",
    "A03:2021-Injection",
    "A04:2021-Insecure-Design",
    "A05:2021-Security-Misconfiguration",
    "A06:2021-Vulnerable-and-Outdated-Components",
    "A07:2021-Identification-and-Authentication-Failures",
    "A08:2021-Software-and-Data-Integrity-Failures",
    "A09:2021-Security-Logging-and-Monitoring-Failures",
    "A10:2021-Server-Side-Request-Forgery",
]


def owasp_for_rule(cwe: Optional[str], category: Optional[str] = None) -> str:
    """Resolve an OWASP Top 10:2021 label for a rule/finding, given its CWE
    (preferred) and coarse category (fallback when CWE is blank/unmapped)."""
    cwe_key = (cwe or "").strip().upper()
    if cwe_key in CWE_TO_OWASP:
        return CWE_TO_OWASP[cwe_key]
    return CATEGORY_FALLBACK.get((category or "").strip().lower(), UNKNOWN_OWASP)
