from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, is_open_cidr


def _ingress_open_to_all(ingress: dict, port: int) -> bool:
    from_port = int(ingress.get("from_port", -1) or -1)
    to_port = int(ingress.get("to_port", -1) or -1)
    if from_port > port or to_port < port:
        return False
    cidr = ingress.get("cidr_blocks") or []
    ipv6 = ingress.get("ipv6_cidr_blocks") or []
    return is_open_cidr(cidr) or is_open_cidr(ipv6)


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_security_group"]):
        a = attrs(res)
        ingress_list = a.get("ingress") or []
        if isinstance(ingress_list, dict):
            ingress_list = [ingress_list]
        for ingress in ingress_list:
            if isinstance(ingress, dict) and _ingress_open_to_all(ingress, 22):
                findings.append(hit(res,
                    "Security group allows SSH from any IP (0.0.0.0/0 or ::/0)",
                    "ingress port 22 open to 0.0.0.0/0 or ::/0"))
                break
    for res in resources_of(document, ["aws_security_group_rule"]):
        a = attrs(res)
        if str(a.get("type", "")).lower() != "ingress":
            continue
        from_port = int(a.get("from_port", -1) or -1)
        to_port = int(a.get("to_port", -1) or -1)
        if from_port <= 22 <= to_port:
            cidr = a.get("cidr_blocks") or []
            ipv6 = a.get("ipv6_cidr_blocks") or []
            if is_open_cidr(cidr) or is_open_cidr(ipv6):
                findings.append(hit(res,
                    "Security group rule allows SSH from any IP",
                    "port 22 open to 0.0.0.0/0 or ::/0"))
    return findings
