from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_opensearch_domain", "aws_elasticsearch_domain"]):
        a = attrs(res)
        endpoint_opts = get_nested(a, "domain_endpoint_options")
        if isinstance(endpoint_opts, list):
            endpoint_opts = endpoint_opts[0] if endpoint_opts else {}
        if not isinstance(endpoint_opts, dict) or not endpoint_opts.get("enforce_https"):
            findings.append(hit(res,
                "OpenSearch/Elasticsearch domain does not enforce HTTPS",
                "domain_endpoint_options.enforce_https=false or not set"))
    return findings
