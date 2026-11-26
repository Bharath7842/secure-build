from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_s3_bucket_versioning"]):
        a = attrs(res)
        ver_cfg = a.get("versioning_configuration") or []
        if isinstance(ver_cfg, list):
            ver_cfg = ver_cfg[0] if ver_cfg else {}
        mfa_delete = ver_cfg.get("mfa_delete", "Disabled") if isinstance(ver_cfg, dict) else "Disabled"
        if str(mfa_delete).lower() != "enabled":
            findings.append(hit(res,
                f"S3 bucket versioning '{res.get('name')}' does not have MFA delete enabled",
                f"versioning_configuration.mfa_delete={mfa_delete!r}"))
    return findings
