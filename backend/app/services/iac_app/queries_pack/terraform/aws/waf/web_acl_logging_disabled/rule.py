from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    # Collect web ACL ARNs / names that have logging configured
    logged_arns = set()
    for res in resources_of(document, ["aws_wafv2_web_acl_logging_configuration"]):
        a = attrs(res)
        arn = a.get("resource_arn", "")
        if arn:
            logged_arns.add(arn)

    findings = []
    for res in resources_of(document, ["aws_wafv2_web_acl"]):
        name = res.get("name", "")
        has_logging = any(name and name in arn for arn in logged_arns)
        if not has_logging and not logged_arns:
            findings.append(hit(res,
                f"WAFv2 web ACL '{name}' does not have logging enabled",
                "No aws_wafv2_web_acl_logging_configuration found"))
    return findings
