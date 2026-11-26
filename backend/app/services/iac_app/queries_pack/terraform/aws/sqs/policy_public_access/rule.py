import json

from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def _policy_allows_public(policy_str: str) -> bool:
    try:
        doc = json.loads(policy_str) if isinstance(policy_str, str) else policy_str
    except (ValueError, TypeError):
        return False
    if not isinstance(doc, dict):
        return False
    for stmt in doc.get("Statement") or []:
        if not isinstance(stmt, dict):
            continue
        if str(stmt.get("Effect", "Allow")).lower() != "allow":
            continue
        principal = stmt.get("Principal")
        is_star = principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*")
        if is_star and not stmt.get("Condition"):
            return True
    return False


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_sqs_queue_policy"]):
        a = attrs(res)
        policy = a.get("policy") or ""
        if _policy_allows_public(policy):
            findings.append(hit(res,
                f"SQS queue policy '{res.get('name')}' allows public access (Principal: '*')",
                "policy Statement has Principal='*' with no Condition"))
    return findings
