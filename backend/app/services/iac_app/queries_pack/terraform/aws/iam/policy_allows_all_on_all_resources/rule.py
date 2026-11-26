import json
from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit

POLICY_RESOURCES = [
    "aws_iam_policy",
    "aws_iam_role_policy",
    "aws_iam_user_policy",
    "aws_iam_group_policy",
]


def _is_star_on_star(policy) -> bool:
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except (json.JSONDecodeError, TypeError):
            return False
    for stmt in policy.get("Statement", []):
        if str(stmt.get("Effect", "")).upper() != "ALLOW":
            continue
        action = stmt.get("Action", [])
        resource = stmt.get("Resource", [])
        if isinstance(action, str):
            action = [action]
        if isinstance(resource, str):
            resource = [resource]
        if "*" in action and "*" in resource:
            return True
    return False


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, POLICY_RESOURCES):
        a = attrs(res)
        policy_str = a.get("policy") or a.get("document") or "{}"
        if _is_star_on_star(policy_str):
            findings.append(hit(res,
                f"IAM policy '{res.get('name')}' allows all actions (*) on all resources (*)",
                "Action: '*', Resource: '*' found in policy"))
    return findings
