import json

IAM_TYPES = {
    "AWS::IAM::Policy", "AWS::IAM::ManagedPolicy",
    "AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group",
}


def _policy_has_wildcard_action(policy_doc) -> bool:
    if isinstance(policy_doc, str):
        try:
            policy_doc = json.loads(policy_doc)
        except (ValueError, TypeError):
            return False
    if not isinstance(policy_doc, dict):
        return False
    for stmt in (policy_doc.get("Statement") or []):
        actions = stmt.get("Action") or []
        if isinstance(actions, str):
            actions = [actions]
        if "*" in actions:
            return True
    return False


def evaluate(document: dict) -> list[dict]:
    findings = []
    for resource in document.get("resources") or []:
        rtype = resource.get("type", "")
        if rtype not in IAM_TYPES:
            continue
        attrs = resource.get("attributes") or {}
        # Check PolicyDocument (for policies and roles)
        for key in ("PolicyDocument", "AssumeRolePolicyDocument"):
            if _policy_has_wildcard_action(attrs.get(key)):
                loc = resource.get("location") or {}
                findings.append({
                    "resource": resource.get("id"),
                    "resource_type": rtype,
                    "message": f"CloudFormation {rtype} grants wildcard action (*) in {key}",
                    "evidence": f"{key} Action contains *",
                    "line_start": loc.get("line_start"),
                })
                break
        # Check inline Policies list
        for policy in (attrs.get("Policies") or []):
            if isinstance(policy, dict) and _policy_has_wildcard_action(policy.get("PolicyDocument")):
                loc = resource.get("location") or {}
                findings.append({
                    "resource": resource.get("id"),
                    "resource_type": rtype,
                    "message": f"CloudFormation {rtype} inline policy grants wildcard action (*)",
                    "evidence": f"Policies[].PolicyDocument Action contains *",
                    "line_start": loc.get("line_start"),
                })
                break
    return findings
