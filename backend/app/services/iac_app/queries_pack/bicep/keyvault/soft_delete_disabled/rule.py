from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["Microsoft.KeyVault/vaults"]):
        a = attrs(res)
        soft_delete = a.get("enableSoftDelete", True)
        retention = a.get("softDeleteRetentionInDays")
        if soft_delete is False or (retention is not None and int(retention) < 7):
            findings.append(hit(res,
                "Bicep Key Vault does not have adequate soft delete configuration",
                f"enableSoftDelete={soft_delete}, softDeleteRetentionInDays={retention}"))
    return findings
