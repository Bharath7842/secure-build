from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_sqs_queue"]):
        a = attrs(res)
        kms_key = a.get("kms_master_key_id") or a.get("sqs_managed_sse_enabled")
        if not kms_key:
            findings.append(hit(res,
                "SQS queue does not have server-side encryption enabled",
                "kms_master_key_id and sqs_managed_sse_enabled are both not set"))
    return findings
