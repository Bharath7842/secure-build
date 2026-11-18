from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_iam_account_password_policy"]):
        a = attrs(res)
        length = a.get("minimum_password_length")
        if length is None or int(length) < 14:
            findings.append(hit(res,
                "IAM password policy minimum length is less than 14",
                f"minimum_password_length={length}"))
    return findings
