from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws:ec2/instance:Instance"]):
        a = attrs(res)
        if a.get("associatePublicIpAddress") is True:
            findings.append(hit(res,
                "Pulumi EC2 instance has a public IP address assigned",
                "associatePublicIpAddress=true"))
    return findings
