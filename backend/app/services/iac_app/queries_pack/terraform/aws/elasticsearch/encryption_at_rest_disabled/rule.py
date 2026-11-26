from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested

RESOURCE_TYPES = ["aws_elasticsearch_domain", "aws_opensearch_domain"]


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, RESOURCE_TYPES):
        a = attrs(res)
        ear = a.get("encrypt_at_rest") or []
        if isinstance(ear, list):
            ear = ear[0] if ear else {}
        if not isinstance(ear, dict):
            ear = {}
        enabled = ear.get("enabled")
        if str(enabled).lower() not in ("true", "1"):
            findings.append(hit(res,
                f"{res.get('type')} '{res.get('name')}' does not have encryption at rest enabled",
                f"encrypt_at_rest.enabled={enabled!r}"))
    return findings
