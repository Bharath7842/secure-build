from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["Microsoft.KeyVault/vaults"]):
        a = attrs(res)
        if not a.get("enablePurgeProtection"):
            findings.append(hit(res,
                "Bicep Key Vault does not have purge protection enabled",
                "enablePurgeProtection=false or not set"))
    return findings
