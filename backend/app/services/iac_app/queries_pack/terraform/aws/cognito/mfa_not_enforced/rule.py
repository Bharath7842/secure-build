from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_cognito_user_pool"]):
        a = attrs(res)
        mfa = str(a.get("mfa_configuration") or "OFF").upper()
        if mfa == "OFF":
            findings.append(hit(res,
                "Cognito user pool does not enforce MFA (mfa_configuration=OFF)",
                "mfa_configuration=OFF"))
    return findings
