from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested


def evaluate(document: dict) -> list[dict]:
    encrypted_buckets = set()
    for res in resources_of(document, ["aws_s3_bucket_server_side_encryption_configuration"]):
        a = attrs(res)
        bucket_ref = a.get("bucket") or ""
        if bucket_ref:
            if "." in bucket_ref:
                bucket_ref = bucket_ref.split(".")[-2] if bucket_ref.count(".") >= 2 else bucket_ref
            encrypted_buckets.add(bucket_ref)

    findings = []
    for res in resources_of(document, ["aws_s3_bucket"]):
        a = attrs(res)
        name = res.get("name") or ""
        if name in encrypted_buckets:
            continue
        # Also accept inline server_side_encryption_configuration
        sse = get_nested(a, "server_side_encryption_configuration")
        if isinstance(sse, list):
            sse = sse[0] if sse else None
        if isinstance(sse, dict):
            continue
        findings.append(hit(res,
            f"S3 bucket '{name}' does not have server-side encryption configured",
            "aws_s3_bucket_server_side_encryption_configuration not found"))
    return findings
