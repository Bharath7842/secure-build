import json
from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_iam_role"]):
        a = attrs(res)
        policy_str = a.get("assume_role_policy", "{}")
        try:
            policy = json.loads(policy_str) if isinstance(policy_str, str) else policy_str
        except (json.JSONDecodeError, TypeError):
            continue
        for stmt in policy.get("Statement", []):
            if str(stmt.get("Effect", "")).upper() != "ALLOW":
                continue
            principal = stmt.get("Principal", {})
            service = principal.get("Service", "") if isinstance(principal, dict) else ""
            if service == "*" or principal == "*":
                findings.append(hit(res,
                    f"IAM role '{res.get('name')}' trust policy allows assumption by all services (*)",
                    f"Principal.Service={service!r}"))
                break
    return findings
