from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws:rds/instance:Instance"]):
        a = attrs(res)
        if a.get("publiclyAccessible") is True:
            findings.append(hit(res,
                "Pulumi RDS instance is publicly accessible",
                "publiclyAccessible=true"))
    return findings
