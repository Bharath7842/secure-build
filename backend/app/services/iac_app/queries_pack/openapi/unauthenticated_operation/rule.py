from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["OpenAPISpec"]):
        a = attrs(res)
        operations = a.get("operations") or []
        for op in operations:
            if not isinstance(op, dict):
                continue
            sec = op.get("security")
            if sec == [] or sec == [{}]:
                path = op.get("path") or op.get("operationId") or "unknown"
                method = op.get("method") or op.get("http_method") or ""
                findings.append(hit(res,
                    f"OpenAPI operation {method.upper()} {path} explicitly disables security",
                    f"security=[] on {method} {path}"))
    return findings
