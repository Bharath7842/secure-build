from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit

OPEN_CIDRS = {"*", "internet", "any", "0.0.0.0/0"}


def _is_open(source: str) -> bool:
    return str(source or "").strip().lower() in OPEN_CIDRS


def _is_ssh_port(port_range: str) -> bool:
    pr = str(port_range or "").strip()
    return pr == "22" or pr == "*" or (pr.startswith("1") and "-" in pr and int(pr.split("-")[0]) <= 22 <= int(pr.split("-")[1]))


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["azurerm_network_security_rule"]):
        a = attrs(res)
        if str(a.get("direction") or "").lower() != "inbound":
            continue
        if str(a.get("access") or "").lower() != "allow":
            continue
        port = str(a.get("destination_port_range") or "")
        source = str(a.get("source_address_prefix") or "")
        if _is_open(source):
            try:
                if _is_ssh_port(port):
                    findings.append(hit(res,
                        "NSG rule allows SSH (port 22) from the internet",
                        f"source={source} dest_port={port}"))
            except Exception:
                pass
    return findings
