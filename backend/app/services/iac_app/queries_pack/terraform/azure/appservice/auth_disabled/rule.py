from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested

APP_SERVICE_TYPES = ["azurerm_app_service", "azurerm_linux_web_app", "azurerm_windows_web_app"]


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, APP_SERVICE_TYPES):
        a = attrs(res)
        auth = get_nested(a, "auth_settings")
        if isinstance(auth, list):
            auth = auth[0] if auth else {}
        if not isinstance(auth, dict) or not auth.get("enabled"):
            findings.append(hit(res,
                f"{res.get('type')} does not have App Service Authentication enabled",
                "auth_settings.enabled=false or not set"))
    return findings
