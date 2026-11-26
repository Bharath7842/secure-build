from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_secretsmanager_secret"]):
        a = attrs(res)
        kms_key = a.get("kms_key_id")
        if not kms_key:
            findings.append(hit(res,
                f"Secrets Manager secret '{res.get('name')}' is not encrypted with a customer-managed KMS key",
                "kms_key_id is not set"))
    return findings
