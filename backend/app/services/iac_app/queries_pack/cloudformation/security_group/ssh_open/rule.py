OPEN_CIDRS = {"0.0.0.0/0", "::/0"}

SG_TYPES = {"AWS::EC2::SecurityGroup", "AWS::RDS::DBSecurityGroup"}


def _port_in_range(from_port, to_port, port):
    try:
        return int(from_port) <= port <= int(to_port)
    except (TypeError, ValueError):
        return False


def evaluate(document: dict) -> list[dict]:
    findings = []
    for resource in document.get("resources") or []:
        if resource.get("type") not in SG_TYPES:
            continue
        attrs = resource.get("attributes") or {}
        ingress_rules = attrs.get("SecurityGroupIngress") or []
        if isinstance(ingress_rules, dict):
            ingress_rules = [ingress_rules]
        loc = resource.get("location") or {}
        for rule in ingress_rules:
            if not isinstance(rule, dict):
                continue
            if _port_in_range(rule.get("FromPort", -1), rule.get("ToPort", -1), 22):
                cidr = rule.get("CidrIp", "") or rule.get("CidrIpv6", "")
                if cidr in OPEN_CIDRS:
                    findings.append({
                        "resource": resource.get("id"),
                        "resource_type": resource.get("type"),
                        "message": f"Security group '{resource.get('name')}' allows SSH from any IP",
                        "evidence": f"SecurityGroupIngress port 22 CidrIp={cidr}",
                        "line_start": loc.get("line_start"),
                    })
                    break
    return findings
