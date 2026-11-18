from app.services.iac_app.scanner.queries.helpers import resources_of, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_default_vpc"]):
        findings.append(hit(res,
            "Default VPC is declared in Terraform — use a custom VPC for production workloads",
            "aws_default_vpc resource present"))
    return findings
