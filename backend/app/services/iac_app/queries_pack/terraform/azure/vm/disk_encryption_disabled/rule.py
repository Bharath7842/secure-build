from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["azurerm_managed_disk"]):
        a = attrs(res)
        if not a.get("disk_encryption_set_id"):
            findings.append(hit(res,
                "Azure managed disk does not have a customer-managed key encryption set attached",
                "disk_encryption_set_id not set"))
    return findings
