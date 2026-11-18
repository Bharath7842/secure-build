from app.services.iac_app.scanner.queries.helpers import resources_of, hit


def evaluate(document: dict) -> list[dict]:
    blocked_buckets = set()
    for res in resources_of(document, ["aws_s3_bucket_public_access_block"]):
        a = res.get("attributes") or {}
        bucket_ref = a.get("bucket") or ""
        if bucket_ref:
            # strip Terraform references like aws_s3_bucket.foo.id or aws_s3_bucket.foo.bucket
            if "." in bucket_ref:
                bucket_ref = bucket_ref.split(".")[-2] if bucket_ref.count(".") >= 2 else bucket_ref
            blocked_buckets.add(bucket_ref)

    findings = []
    for res in resources_of(document, ["aws_s3_bucket"]):
        name = res.get("name") or ""
        if name not in blocked_buckets:
            findings.append(hit(res,
                f"S3 bucket '{name}' has no aws_s3_bucket_public_access_block",
                "aws_s3_bucket_public_access_block not found"))
    return findings
