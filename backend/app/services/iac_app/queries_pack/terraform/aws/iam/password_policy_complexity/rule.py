from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    flags = [
        "require_uppercase_characters",
        "require_lowercase_characters",
        "require_numbers",
        "require_symbols",
    ]
    for res in resources_of(document, ["aws_iam_account_password_policy"]):
        a = attrs(res)
        missing = [f for f in flags if not a.get(f)]
        if missing:
            findings.append(hit(res,
                "IAM password policy missing complexity requirement(s)",
                ", ".join(missing) + " not set to true"))
    return findings
