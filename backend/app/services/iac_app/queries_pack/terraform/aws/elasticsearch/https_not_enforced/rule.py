from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit

RESOURCE_TYPES = ["aws_elasticsearch_domain", "aws_opensearch_domain"]


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, RESOURCE_TYPES):
        a = attrs(res)
        opts = a.get("domain_endpoint_options") or []
        if isinstance(opts, list):
            opts = opts[0] if opts else {}
        if not isinstance(opts, dict):
            opts = {}
        enforce = opts.get("enforce_https")
        if str(enforce).lower() not in ("true", "1"):
            findings.append(hit(res,
                f"{res.get('type')} '{res.get('name')}' does not enforce HTTPS",
                f"domain_endpoint_options.enforce_https={enforce!r}"))
    return findings
