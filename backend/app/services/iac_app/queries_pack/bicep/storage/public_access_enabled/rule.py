from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["Microsoft.Storage/storageAccounts"]):
        a = attrs(res)
        public = a.get("allowBlobPublicAccess")
        if public is True or public is None:
            findings.append(hit(res,
                "Bicep Storage account allows public blob access",
                f"allowBlobPublicAccess={public if public is not None else 'not set (defaults to true)'}"))
    return findings
