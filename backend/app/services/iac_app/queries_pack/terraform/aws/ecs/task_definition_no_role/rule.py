from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_ecs_task_definition"]):
        a = attrs(res)
        if not a.get("task_role_arn"):
            findings.append(hit(res,
                "ECS task definition has no task IAM role (task_role_arn not set)",
                "task_role_arn not set"))
    return findings
