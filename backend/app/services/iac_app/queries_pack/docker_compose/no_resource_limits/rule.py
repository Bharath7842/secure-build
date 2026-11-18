from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["compose_service"]):
        a = attrs(res)
        deploy = a.get("deploy") or {}
        if isinstance(deploy, dict):
            resources_config = deploy.get("resources") or {}
            limits = resources_config.get("limits") if isinstance(resources_config, dict) else None
        else:
            limits = None
        if not limits:
            findings.append(hit(res,
                f"Docker Compose service '{res.get('name')}' has no resource limits defined",
                "deploy.resources.limits not set"))
    return findings
