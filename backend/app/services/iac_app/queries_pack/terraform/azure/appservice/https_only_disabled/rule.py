from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit

APP_SERVICE_TYPES = [
    "azurerm_app_service",
    "azurerm_linux_web_app",
    "azurerm_windows_web_app",
    "azurerm_linux_function_app",
    "azurerm_windows_function_app",
]


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, APP_SERVICE_TYPES):
        a = attrs(res)
        if a.get("https_only") is False:
            findings.append(hit(res,
                f"{res.get('type')} does not enforce HTTPS-only traffic",
                "https_only=false"))
    return findings
