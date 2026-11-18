from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["google_storage_bucket"]):
        a = attrs(res)
        logging = get_nested(a, "logging")
        if isinstance(logging, list):
            logging = logging[0] if logging else None
        if not logging:
            findings.append(hit(res,
                "GCS bucket does not have access logging configured",
                "logging block not set"))
    return findings
