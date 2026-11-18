from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["OpenAPISpec"]):
        a = attrs(res)
        schemes = a.get("security_definitions") or a.get("securityDefinitions") or {}
        components = a.get("components") or {}
        schemes_v3 = components.get("securitySchemes") or components.get("security_schemes") or {}
        if not schemes and not schemes_v3:
            findings.append(hit(res,
                "OpenAPI specification defines no security schemes",
                "security_definitions/components.securitySchemes is empty"))
    return findings
