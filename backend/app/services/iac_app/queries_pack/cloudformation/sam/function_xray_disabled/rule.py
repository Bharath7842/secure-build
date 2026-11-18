from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["AWS::Serverless::Function"]):
        a = attrs(res)
        tracing = str(a.get("Tracing") or "PassThrough").strip()
        if tracing.lower() != "active":
            findings.append(hit(res,
                "SAM Serverless Function does not have X-Ray active tracing enabled",
                f"Tracing={tracing}"))
    return findings
