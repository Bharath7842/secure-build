from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["google_storage_bucket"]):
        a = attrs(res)
        versioning = get_nested(a, "versioning")
        if isinstance(versioning, list):
            versioning = versioning[0] if versioning else {}
        enabled = (versioning or {}).get("enabled") if isinstance(versioning, dict) else False
        if not enabled:
            findings.append(hit(res,
                "GCS bucket versioning is disabled",
                "versioning.enabled=false or not set"))
    return findings
