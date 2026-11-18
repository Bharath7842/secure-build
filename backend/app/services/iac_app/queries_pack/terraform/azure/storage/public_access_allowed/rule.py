from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["azurerm_storage_account"]):
        a = attrs(res)
        public = a.get("allow_nested_items_to_be_public")
        if public is True or public is None:
            findings.append(hit(res,
                "Azure Storage account allows public blob/container access",
                f"allow_nested_items_to_be_public={public if public is not None else 'not set (defaults to true)'}"))
    return findings
