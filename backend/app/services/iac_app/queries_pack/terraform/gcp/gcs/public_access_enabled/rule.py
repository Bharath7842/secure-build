from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["google_storage_bucket"]):
        a = attrs(res)
        if not a.get("uniform_bucket_level_access"):
            findings.append(hit(res,
                "GCS bucket does not enforce uniform bucket-level access",
                "uniform_bucket_level_access=false or not set"))
    return findings
