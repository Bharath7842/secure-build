from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_instance"]):
        a = attrs(res)
        if a.get("associate_public_ip_address") is True:
            findings.append(hit(res,
                "EC2 instance has associate_public_ip_address = true",
                "associate_public_ip_address = true"))
    return findings
