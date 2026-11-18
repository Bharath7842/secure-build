from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["google_compute_instance"]):
        a = attrs(res)
        network_interfaces = a.get("network_interface") or []
        if isinstance(network_interfaces, dict):
            network_interfaces = [network_interfaces]
        for ni in network_interfaces:
            if not isinstance(ni, dict):
                continue
            access_config = ni.get("access_config")
            if access_config is not None and access_config != []:
                findings.append(hit(res,
                    "GCE instance has a public IP via access_config",
                    "network_interface.access_config is present"))
                break
    return findings
