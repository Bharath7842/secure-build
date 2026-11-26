from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_lb", "aws_alb"]):
        a = attrs(res)
        lb_type = str(a.get("load_balancer_type", "application")).lower()
        if lb_type != "application":
            continue
        protection = a.get("enable_deletion_protection")
        if str(protection).lower() not in ("true", "1"):
            findings.append(hit(res,
                f"ALB '{res.get('name')}' has deletion protection disabled",
                f"enable_deletion_protection={protection!r}"))
    return findings
