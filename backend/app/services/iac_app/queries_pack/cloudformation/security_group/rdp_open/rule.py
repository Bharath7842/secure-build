OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def evaluate(document: dict) -> list[dict]:
    findings = []
    for resource in document.get("resources") or []:
        if resource.get("type") not in ("AWS::EC2::SecurityGroup",):
            continue
        attrs = resource.get("attributes") or {}
        ingress_rules = attrs.get("SecurityGroupIngress") or []
        if isinstance(ingress_rules, dict):
            ingress_rules = [ingress_rules]
        loc = resource.get("location") or {}
        for rule in ingress_rules:
            if not isinstance(rule, dict):
                continue
            try:
                fp = int(rule.get("FromPort", -1))
                tp = int(rule.get("ToPort", -1))
            except (TypeError, ValueError):
                continue
            if fp <= 3389 <= tp:
                cidr = rule.get("CidrIp", "") or rule.get("CidrIpv6", "")
                if cidr in OPEN_CIDRS:
                    findings.append({
                        "resource": resource.get("id"),
                        "resource_type": resource.get("type"),
                        "message": f"Security group '{resource.get('name')}' allows RDP from any IP",
                        "evidence": f"SecurityGroupIngress port 3389 CidrIp={cidr}",
                        "line_start": loc.get("line_start"),
                    })
                    break
    return findings
