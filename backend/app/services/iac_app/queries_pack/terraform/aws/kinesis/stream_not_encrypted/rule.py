from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_kinesis_stream"]):
        a = attrs(res)
        sse = a.get("server_side_encryption") or []
        if isinstance(sse, list):
            sse = sse[0] if sse else {}
        enc_type = sse.get("encryption_type", "NONE") if isinstance(sse, dict) else "NONE"
        if str(enc_type).upper() not in ("KMS",):
            findings.append(hit(res,
                f"Kinesis stream '{res.get('name')}' does not have server-side encryption enabled",
                f"server_side_encryption.encryption_type={enc_type!r}"))
    return findings
