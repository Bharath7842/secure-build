"""Default OWASP reference URL sets used to prefill Project.owasp_urls."""

TOP10: list[str] = [
    "https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/",
    "https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/",
    "https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/",
    "https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/",
    "https://owasp.org/Top10/2025/A05_2025-Injection/",
    "https://owasp.org/Top10/2025/A06_2025-Insecure_Design/",
    "https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/",
    "https://owasp.org/Top10/2025/A08_2025-Software_and_Data_Integrity_Failures/",
    "https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Monitoring_Failures/",
    "https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/",
]

CHEAT_SHEETS: list[str] = [
    "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html",
    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
    "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
]

TOP15: list[str] = TOP10 + CHEAT_SHEETS


def urls_for_mode(mode: str) -> list[str]:
    """Return the default OWASP reference URLs for a given owasp_mode.

    "custom" (or any unrecognized mode) yields no defaults, since the
    caller is expected to supply their own URL list in that case.
    """
    if mode == "top10":
        return list(TOP10)
    if mode == "top15":
        return list(TOP15)
    return []
