from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_cloudfront_distribution"]):
        a = attrs(res)
        origins = a.get("origin") or []
        if not isinstance(origins, list):
            origins = [origins]
        for origin in origins:
            if not isinstance(origin, dict):
                continue
            domain = origin.get("domain_name", "")
            # Only check S3 origins
            if ".s3." not in str(domain) and not str(domain).endswith(".s3.amazonaws.com"):
                continue
            s3_cfg = origin.get("s3_origin_config") or []
            if isinstance(s3_cfg, list):
                s3_cfg = s3_cfg[0] if s3_cfg else {}
            oac_id = origin.get("origin_access_control_id", "")
            oai = s3_cfg.get("origin_access_identity", "") if isinstance(s3_cfg, dict) else ""
            if not oai and not oac_id:
                findings.append(hit(res,
                    f"CloudFront distribution '{res.get('name')}' S3 origin '{domain}' is not using OAI or OAC",
                    "s3_origin_config.origin_access_identity and origin_access_control_id are both absent"))
    return findings
