from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested, is_falsey


def evaluate(document: dict) -> list[dict]:
    logged_buckets = set()
    for res in resources_of(document, ["aws_s3_bucket_logging"]):
        a = attrs(res)
        bucket_ref = a.get("bucket") or ""
        if bucket_ref:
            if "." in bucket_ref:
                bucket_ref = bucket_ref.split(".")[-2] if bucket_ref.count(".") >= 2 else bucket_ref
            logged_buckets.add(bucket_ref)

    findings = []
    for res in resources_of(document, ["aws_s3_bucket"]):
        a = attrs(res)
        name = res.get("name") or ""
        if name in logged_buckets:
            continue
        logging_block = get_nested(a, "logging")
        if isinstance(logging_block, list):
            logging_block = logging_block[0] if logging_block else None
        if isinstance(logging_block, dict) and logging_block.get("target_bucket"):
            continue
        findings.append(hit(res,
            f"S3 bucket '{name}' does not have access logging enabled",
            "logging block absent or target_bucket not set"))
    return findings
