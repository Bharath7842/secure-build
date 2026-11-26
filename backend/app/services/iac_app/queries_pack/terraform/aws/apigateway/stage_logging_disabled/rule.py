from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_api_gateway_stage"]):
        a = attrs(res)
        log_settings = a.get("access_log_settings") or []
        if isinstance(log_settings, dict):
            log_settings = [log_settings]
        has_logging = False
        if isinstance(log_settings, list) and log_settings:
            first = log_settings[0] if isinstance(log_settings[0], dict) else {}
            has_logging = bool(first.get("destination_arn"))
        if not has_logging:
            findings.append(hit(res,
                f"API Gateway stage '{res.get('name')}' has access logging disabled",
                "access_log_settings.destination_arn is not configured"))
    return findings
