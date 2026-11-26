from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    # Collect all LB ARNs that have a WAF association
    protected_arns = set()
    for res in resources_of(document, ["aws_wafv2_web_acl_association"]):
        a = attrs(res)
        arn = a.get("resource_arn", "")
        if arn:
            protected_arns.add(arn)

    findings = []
    for res in resources_of(document, ["aws_lb", "aws_alb"]):
        a = attrs(res)
        lb_type = str(a.get("load_balancer_type", "application")).lower()
        if lb_type != "application":
            continue
        # Check by name reference since ARNs may be computed
        name = res.get("name", "")
        has_waf = any(name and name in arn for arn in protected_arns)
        if not has_waf and not protected_arns:
            findings.append(hit(res,
                f"ALB '{name}' does not have a WAF web ACL associated",
                "No aws_wafv2_web_acl_association found for this ALB"))
    return findings
