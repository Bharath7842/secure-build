from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_iam_account_password_policy"]):
        a = attrs(res)
        age = a.get("max_password_age")
        if age is None or int(age) == 0 or int(age) > 90:
            findings.append(hit(res,
                "IAM password policy max age exceeds 90 days or is not set",
                f"max_password_age={age}"))
    return findings
