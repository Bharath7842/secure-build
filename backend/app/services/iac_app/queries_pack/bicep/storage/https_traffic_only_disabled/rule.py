from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["Microsoft.Storage/storageAccounts"]):
        a = attrs(res)
        https_only = a.get("supportsHttpsTrafficOnly", True)
        if https_only is False:
            findings.append(hit(res,
                "Bicep Storage account does not enforce HTTPS-only traffic",
                "supportsHttpsTrafficOnly=false"))
    return findings
