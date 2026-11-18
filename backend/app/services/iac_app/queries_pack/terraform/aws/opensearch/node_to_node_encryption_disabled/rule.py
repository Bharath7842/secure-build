from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_opensearch_domain", "aws_elasticsearch_domain"]):
        a = attrs(res)
        n2n = get_nested(a, "node_to_node_encryption")
        if isinstance(n2n, list):
            n2n = n2n[0] if n2n else {}
        if not isinstance(n2n, dict) or not n2n.get("enabled"):
            findings.append(hit(res,
                "OpenSearch/Elasticsearch domain does not have node-to-node encryption enabled",
                "node_to_node_encryption.enabled=false or not set"))
    return findings
