from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["AWS::Serverless::Function"]):
        a = attrs(res)
        if not a.get("VpcConfig"):
            findings.append(hit(res,
                "SAM Serverless Function is not configured to run in a VPC",
                "VpcConfig not set"))
    return findings
