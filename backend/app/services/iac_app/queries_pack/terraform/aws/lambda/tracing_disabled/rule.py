from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_lambda_function"]):
        a = attrs(res)
        tracing = get_nested(a, "tracing_config")
        if isinstance(tracing, list):
            tracing = tracing[0] if tracing else {}
        if not isinstance(tracing, dict):
            tracing = {}
        mode = str(tracing.get("mode", "PassThrough")).strip()
        if mode.lower() != "active":
            findings.append(hit(res,
                "Lambda function X-Ray tracing is not set to Active",
                f"tracing_config.mode={mode or 'not set'}"))
    return findings
