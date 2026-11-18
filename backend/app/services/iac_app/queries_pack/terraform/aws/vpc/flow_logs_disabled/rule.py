from app.services.iac_app.scanner.queries.helpers import resources_of, hit


def evaluate(document: dict) -> list[dict]:
    vpcs_with_flow_logs = set()
    for res in resources_of(document, ["aws_flow_log"]):
        a = res.get("attributes") or {}
        vpc_id = a.get("vpc_id") or ""
        if "." in vpc_id:
            vpc_id = vpc_id.split(".")[-2] if vpc_id.count(".") >= 2 else vpc_id
        if vpc_id:
            vpcs_with_flow_logs.add(vpc_id)

    findings = []
    for res in resources_of(document, ["aws_vpc"]):
        name = res.get("name") or ""
        if name not in vpcs_with_flow_logs:
            findings.append(hit(res,
                f"VPC '{name}' does not have flow logs enabled",
                "no aws_flow_log resource found for this VPC"))
    return findings
