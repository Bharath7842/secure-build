from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_iam_account_password_policy"]):
        a = attrs(res)
        reuse = a.get("password_reuse_prevention")
        if reuse is None or int(reuse) < 24:
            findings.append(hit(res,
                "IAM password policy allows reuse within fewer than 24 previous passwords",
                f"password_reuse_prevention={reuse}"))
    return findings
