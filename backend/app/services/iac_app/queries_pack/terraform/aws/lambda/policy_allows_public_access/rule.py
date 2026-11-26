import json
from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def _policy_allows_public(policy_str: str) -> bool:
    try:
        policy = json.loads(policy_str) if isinstance(policy_str, str) else policy_str
    except (json.JSONDecodeError, TypeError):
        return False
    for stmt in policy.get("Statement", []):
        principal = stmt.get("Principal", "")
        effect = str(stmt.get("Effect", "")).upper()
        if effect != "ALLOW":
            continue
        if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
            return True
    return False


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_lambda_permission"]):
        a = attrs(res)
        principal = str(a.get("principal", ""))
        if principal == "*":
            findings.append(hit(res,
                f"Lambda permission '{res.get('name')}' grants access to all principals (*)",
                f"principal={principal!r}"))
    return findings
