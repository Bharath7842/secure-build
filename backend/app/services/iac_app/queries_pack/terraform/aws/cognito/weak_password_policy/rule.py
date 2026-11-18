from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_cognito_user_pool"]):
        a = attrs(res)
        policy = get_nested(a, "password_policy")
        if isinstance(policy, list):
            policy = policy[0] if policy else {}
        if not isinstance(policy, dict):
            findings.append(hit(res,
                "Cognito user pool has no password policy configured",
                "password_policy not set"))
            continue
        min_len = int(policy.get("minimum_length") or 8)
        missing = []
        if min_len < 14:
            missing.append(f"minimum_length={min_len} (< 14)")
        for req in ("require_uppercase", "require_lowercase", "require_numbers", "require_symbols"):
            if not policy.get(req, True):
                missing.append(f"{req}=false")
        if missing:
            findings.append(hit(res,
                "Cognito user pool has a weak password policy",
                ", ".join(missing)))
    return findings
