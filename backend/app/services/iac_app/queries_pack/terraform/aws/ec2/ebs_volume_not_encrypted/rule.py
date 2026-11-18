from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_ebs_volume"]):
        a = attrs(res)
        if a.get("encrypted") is not True:
            findings.append(hit(res,
                "EBS volume is not encrypted at rest",
                f"encrypted={a.get('encrypted', 'not set')}"))
    return findings
