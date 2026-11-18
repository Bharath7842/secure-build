import json
from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def _has_wildcard_action(policy_str: str) -> bool:
    if not policy_str:
        return False
    try:
        doc = json.loads(policy_str) if isinstance(policy_str, str) else policy_str
    except (ValueError, TypeError):
        return False
    for stmt in (doc.get("Statement") or []):
        actions = stmt.get("Action") or []
        if isinstance(actions, str):
            actions = [actions]
        if "*" in actions:
            return True
    return False


def evaluate(document: dict) -> list[dict]:
    findings = []
    types = ["aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"]
    for res in resources_of(document, types):
        a = attrs(res)
        policy = a.get("policy")
        if _has_wildcard_action(policy):
            findings.append(hit(res,
                "IAM policy grants wildcard action (*) — overly permissive",
                "Action contains *"))
    return findings
