from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_api_gateway_stage"]):
        a = attrs(res)
        if not (a.get("web_acl_arn") or "").strip():
            findings.append(hit(res,
                f"API Gateway stage '{res.get('name')}' is not associated with a WAF web ACL",
                "web_acl_arn is not configured"))
    return findings
