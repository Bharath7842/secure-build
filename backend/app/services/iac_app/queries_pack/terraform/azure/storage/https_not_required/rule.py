from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["azurerm_storage_account"]):
        a = attrs(res)
        https_only = a.get("enable_https_traffic_only") if "enable_https_traffic_only" in a else a.get("https_traffic_only_enabled")
        if https_only is False:
            findings.append(hit(res,
                "Azure Storage account does not require HTTPS-only traffic",
                "enable_https_traffic_only=false"))
    return findings
