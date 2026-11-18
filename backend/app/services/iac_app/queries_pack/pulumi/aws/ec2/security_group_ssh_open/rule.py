from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def _port_includes_ssh(from_port, to_port) -> bool:
    try:
        return int(from_port) <= 22 <= int(to_port)
    except (TypeError, ValueError):
        return False


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws:ec2/securityGroup:SecurityGroup"]):
        a = attrs(res)
        ingress_rules = a.get("ingress") or []
        if not isinstance(ingress_rules, list):
            continue
        for rule in ingress_rules:
            if not isinstance(rule, dict):
                continue
            cidrs = (rule.get("cidrBlocks") or []) + (rule.get("ipv6CidrBlocks") or [])
            from_port = rule.get("fromPort", 0)
            to_port = rule.get("toPort", 65535)
            if any(c in OPEN_CIDRS for c in cidrs) and _port_includes_ssh(from_port, to_port):
                findings.append(hit(res,
                    "Pulumi Security Group allows SSH (port 22) from the internet",
                    f"ingress fromPort={from_port} toPort={to_port} cidr={cidrs}"))
                break
    return findings
