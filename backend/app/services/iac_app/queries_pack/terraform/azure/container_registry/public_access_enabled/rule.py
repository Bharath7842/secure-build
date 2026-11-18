from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["azurerm_container_registry"]):
        a = attrs(res)
        sku = str(a.get("sku") or "Basic").title()
        if sku in ("Basic", "Standard"):
            continue
        if a.get("public_network_access_enabled", True) is not False:
            findings.append(hit(res,
                "Azure Container Registry (Premium SKU) allows public network access",
                f"public_network_access_enabled=true or not set, sku={sku}"))
    return findings
