from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_cloudfront_distribution"]):
        a = attrs(res)
        if not a.get("web_acl_id"):
            findings.append(hit(res,
                "CloudFront distribution has no WAF web ACL attached",
                "web_acl_id not set"))
    return findings
