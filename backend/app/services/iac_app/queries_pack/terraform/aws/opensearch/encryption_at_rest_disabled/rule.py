from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_opensearch_domain", "aws_elasticsearch_domain"]):
        a = attrs(res)
        ear = get_nested(a, "encrypt_at_rest")
        if isinstance(ear, list):
            ear = ear[0] if ear else {}
        if not isinstance(ear, dict) or not ear.get("enabled"):
            findings.append(hit(res,
                "OpenSearch/Elasticsearch domain does not have encryption at rest enabled",
                "encrypt_at_rest.enabled=false or not set"))
    return findings
