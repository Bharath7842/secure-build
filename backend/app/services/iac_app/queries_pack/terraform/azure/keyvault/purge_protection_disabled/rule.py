from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["azurerm_key_vault"]):
        a = attrs(res)
        if not a.get("purge_protection_enabled"):
            findings.append(hit(res,
                "Azure Key Vault does not have purge protection enabled",
                "purge_protection_enabled=false or not set"))
    return findings
