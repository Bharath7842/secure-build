from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["azurerm_key_vault"]):
        a = attrs(res)
        retention_days = a.get("soft_delete_retention_days")
        if not retention_days or int(retention_days) < 7:
            findings.append(hit(res,
                "Azure Key Vault does not have soft delete enabled with sufficient retention",
                f"soft_delete_retention_days={retention_days or 'not set'}"))
    return findings
