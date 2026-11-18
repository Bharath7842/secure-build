from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["OpenAPISpec"]):
        a = attrs(res)
        servers = a.get("servers") or []
        for server in servers:
            if isinstance(server, dict):
                url = str(server.get("url") or "").lower()
            else:
                url = str(server or "").lower()
            if url.startswith("http://"):
                findings.append(hit(res,
                    f"OpenAPI specification server URL uses HTTP: {url}",
                    f"server.url={url}"))
    return findings
