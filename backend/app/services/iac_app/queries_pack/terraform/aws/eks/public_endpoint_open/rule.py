from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested, is_open_cidr


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_eks_cluster"]):
        a = attrs(res)
        vpc_config = get_nested(a, "vpc_config")
        if isinstance(vpc_config, list):
            vpc_config = vpc_config[0] if vpc_config else {}
        if not isinstance(vpc_config, dict):
            continue
        if not vpc_config.get("endpoint_public_access", True):
            continue
        cidrs = vpc_config.get("public_access_cidrs") or ["0.0.0.0/0"]
        if is_open_cidr(cidrs):
            findings.append(hit(res,
                "EKS cluster API endpoint is publicly accessible from any IP",
                f"endpoint_public_access=true, public_access_cidrs={cidrs}"))
    return findings
