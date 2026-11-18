from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested


def evaluate(document: dict) -> list[dict]:
    # Collect buckets that have versioning via aws_s3_bucket_versioning
    versioned_buckets = set()
    for res in resources_of(document, ["aws_s3_bucket_versioning"]):
        a = attrs(res)
        bucket_ref = a.get("bucket") or ""
        config = get_nested(a, "versioning_configuration") or {}
        if isinstance(config, list):
            config = config[0] if config else {}
        if str(config.get("status", "")).lower() == "enabled":
            if "." in bucket_ref:
                bucket_ref = bucket_ref.split(".")[-2] if bucket_ref.count(".") >= 2 else bucket_ref
            versioned_buckets.add(bucket_ref)

    findings = []
    for res in resources_of(document, ["aws_s3_bucket"]):
        a = attrs(res)
        name = res.get("name") or ""
        # Check inline versioning block
        versioning = get_nested(a, "versioning")
        if isinstance(versioning, list):
            versioning = versioning[0] if versioning else {}
        if isinstance(versioning, dict) and versioning.get("enabled"):
            continue
        if name in versioned_buckets:
            continue
        findings.append(hit(res,
            f"S3 bucket '{name}' does not have versioning enabled",
            "versioning.enabled not set or false"))
    return findings
