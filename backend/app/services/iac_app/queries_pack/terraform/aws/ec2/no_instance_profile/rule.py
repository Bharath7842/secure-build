from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_instance"]):
        a = attrs(res)
        profile = a.get("iam_instance_profile")
        if not profile:
            findings.append(hit(res,
                f"EC2 instance '{res.get('name')}' does not have an IAM instance profile",
                "iam_instance_profile is not set"))
    return findings
