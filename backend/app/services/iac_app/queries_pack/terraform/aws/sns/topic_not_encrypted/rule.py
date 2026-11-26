from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_sns_topic"]):
        a = attrs(res)
        if not (a.get("kms_master_key_id") or "").strip():
            findings.append(hit(res,
                f"SNS topic '{res.get('name')}' is not encrypted with a KMS key",
                "kms_master_key_id is not set"))
    return findings
