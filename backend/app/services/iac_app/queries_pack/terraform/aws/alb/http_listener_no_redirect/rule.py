from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_lb_listener", "aws_alb_listener"]):
        a = attrs(res)
        port = str(a.get("port") or "").strip()
        protocol = str(a.get("protocol") or "").upper()
        if port != "80" and protocol != "HTTP":
            continue
        default_action = get_nested(a, "default_action")
        if isinstance(default_action, list):
            default_action = default_action[0] if default_action else {}
        if not isinstance(default_action, dict):
            continue
        action_type = str(default_action.get("type") or "").lower()
        if action_type not in ("redirect",):
            findings.append(hit(res,
                "ALB HTTP listener does not redirect to HTTPS",
                f"default_action.type={action_type} (should be redirect to HTTPS)"))
    return findings
