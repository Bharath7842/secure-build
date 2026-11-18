from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["OpenAPISpec"]):
        a = attrs(res)
        global_security = a.get("security") or []
        schemes = a.get("security_definitions") or a.get("securityDefinitions") or {}
        components = a.get("components") or {}
        schemes_v3 = components.get("securitySchemes") or {}
        if (schemes or schemes_v3) and not global_security:
            findings.append(hit(res,
                "OpenAPI specification has security schemes but no global security requirement",
                "security: [] at spec level"))
    return findings
