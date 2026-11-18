from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["OpenAPISpec"]):
        a = attrs(res)
        schemes = a.get("security_definitions") or a.get("securityDefinitions") or {}
        for scheme_name, scheme in (schemes.items() if isinstance(schemes, dict) else []):
            if isinstance(scheme, dict):
                scheme_in = str(scheme.get("in") or "").lower()
                scheme_type = str(scheme.get("type") or "").lower()
                if scheme_type == "apikey" and scheme_in == "query":
                    findings.append(hit(res,
                        f"OpenAPI security scheme '{scheme_name}' passes API key in query string",
                        f"securityScheme.in=query"))
    return findings
