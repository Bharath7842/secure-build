from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_lb", "aws_alb"]):
        a = attrs(res)
        lb_type = str(a.get("load_balancer_type") or "application").lower()
        if lb_type == "gateway":
            continue
        logs = get_nested(a, "access_logs")
        if isinstance(logs, list):
            logs = logs[0] if logs else {}
        if not isinstance(logs, dict) or not logs.get("enabled"):
            findings.append(hit(res,
                f"Load balancer does not have access logging enabled",
                "access_logs.enabled=false or not set"))
    return findings
