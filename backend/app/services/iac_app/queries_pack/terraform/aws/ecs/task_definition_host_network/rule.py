from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_ecs_task_definition"]):
        a = attrs(res)
        mode = str(a.get("network_mode") or "bridge").lower()
        if mode == "host":
            findings.append(hit(res,
                "ECS task definition uses host network mode (network_mode=host)",
                f"network_mode={mode}"))
    return findings
