from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["AWS::Serverless::Api"]):
        a = attrs(res)
        auth = a.get("Auth") or {}
        if not auth or not (isinstance(auth, dict) and (auth.get("DefaultAuthorizer") or auth.get("Authorizers"))):
            findings.append(hit(res,
                "SAM Serverless API has no authentication/authorization configured",
                "Auth block not set or has no DefaultAuthorizer/Authorizers"))
    return findings
