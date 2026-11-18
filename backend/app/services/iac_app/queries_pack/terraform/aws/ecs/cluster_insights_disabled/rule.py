from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_ecs_cluster"]):
        a = attrs(res)
        settings = a.get("setting") or []
        if isinstance(settings, dict):
            settings = [settings]
        insights_enabled = any(
            str(s.get("name") or "").lower() == "containerinsights"
            and str(s.get("value") or "").lower() == "enabled"
            for s in settings if isinstance(s, dict)
        )
        if not insights_enabled:
            findings.append(hit(res,
                "ECS cluster does not have Container Insights enabled",
                "setting containerInsights=enabled not found"))
    return findings
