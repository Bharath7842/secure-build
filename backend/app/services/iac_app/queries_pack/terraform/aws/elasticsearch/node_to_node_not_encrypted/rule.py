from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit

RESOURCE_TYPES = ["aws_elasticsearch_domain", "aws_opensearch_domain"]


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, RESOURCE_TYPES):
        a = attrs(res)
        n2n = a.get("node_to_node_encryption") or []
        if isinstance(n2n, list):
            n2n = n2n[0] if n2n else {}
        if not isinstance(n2n, dict):
            n2n = {}
        enabled = n2n.get("enabled")
        if str(enabled).lower() not in ("true", "1"):
            findings.append(hit(res,
                f"{res.get('type')} '{res.get('name')}' does not have node-to-node encryption enabled",
                f"node_to_node_encryption.enabled={enabled!r}"))
    return findings
