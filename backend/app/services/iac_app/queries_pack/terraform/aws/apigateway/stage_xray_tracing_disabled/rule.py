from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_api_gateway_stage"]):
        a = attrs(res)
        enabled = a.get("xray_tracing_enabled")
        if str(enabled).lower() not in ("true", "1"):
            findings.append(hit(res,
                f"API Gateway stage '{res.get('name')}' does not have X-Ray tracing enabled",
                f"xray_tracing_enabled={enabled!r}"))
    return findings
