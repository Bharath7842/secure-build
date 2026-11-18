from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_lambda_function_url"]):
        a = attrs(res)
        auth_type = str(a.get("authorization_type", "NONE")).upper()
        if auth_type == "NONE":
            findings.append(hit(res,
                "Lambda function URL is publicly accessible (authorization_type = NONE)",
                "authorization_type = NONE"))
    return findings
