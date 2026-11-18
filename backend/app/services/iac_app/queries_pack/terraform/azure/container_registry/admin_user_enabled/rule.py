from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["azurerm_container_registry"]):
        a = attrs(res)
        if a.get("admin_enabled") is True:
            findings.append(hit(res,
                "Azure Container Registry has the admin user account enabled",
                "admin_enabled=true"))
    return findings
