from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested

SECURE_POLICIES = {"redirect-to-https", "https-only"}


def _check_behavior(behavior, label):
    if not isinstance(behavior, dict):
        return None
    policy = str(behavior.get("viewer_protocol_policy") or "allow-all").lower()
    if policy not in SECURE_POLICIES:
        return f"{label} viewer_protocol_policy={policy}"
    return None


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_cloudfront_distribution"]):
        a = attrs(res)
        default_cb = get_nested(a, "default_cache_behavior")
        if isinstance(default_cb, list):
            default_cb = default_cb[0] if default_cb else {}
        err = _check_behavior(default_cb, "default_cache_behavior")
        if err:
            findings.append(hit(res,
                "CloudFront distribution allows HTTP (not enforcing HTTPS)",
                err))
            continue
        for i, cb in enumerate(a.get("ordered_cache_behavior") or []):
            err = _check_behavior(cb, f"ordered_cache_behavior[{i}]")
            if err:
                findings.append(hit(res,
                    "CloudFront distribution allows HTTP on a cache behavior",
                    err))
                break
    return findings
