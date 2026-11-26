from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_cloudwatch_log_group"]):
        a = attrs(res)
        if not (a.get("kms_key_id") or "").strip():
            findings.append(hit(res,
                f"CloudWatch Log Group '{res.get('name')}' is not encrypted with a KMS key",
                "kms_key_id is not set"))
    return findings
