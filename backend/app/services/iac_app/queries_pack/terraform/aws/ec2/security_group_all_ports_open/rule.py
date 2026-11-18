from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, is_open_cidr


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_security_group"]):
        a = attrs(res)
        ingress_list = a.get("ingress") or []
        if isinstance(ingress_list, dict):
            ingress_list = [ingress_list]
        for ingress in ingress_list:
            if not isinstance(ingress, dict):
                continue
            from_port = int(ingress.get("from_port", -1) or -1)
            to_port = int(ingress.get("to_port", -1) or -1)
            protocol = str(ingress.get("protocol", "tcp")).lower()
            if protocol in ("-1", "all") or (from_port == 0 and to_port in (0, 65535)):
                cidr = ingress.get("cidr_blocks") or []
                ipv6 = ingress.get("ipv6_cidr_blocks") or []
                if is_open_cidr(cidr) or is_open_cidr(ipv6):
                    findings.append(hit(res,
                        "Security group allows all traffic from any IP",
                        f"ingress ports {from_port}-{to_port}/{protocol} open to 0.0.0.0/0"))
                    break
    return findings
