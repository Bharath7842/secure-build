from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["google_container_cluster"]):
        a = attrs(res)
        auth_networks = get_nested(a, "master_authorized_networks_config")
        if isinstance(auth_networks, list):
            auth_networks = auth_networks[0] if auth_networks else None
        if not auth_networks:
            findings.append(hit(res,
                "GKE cluster control plane is not restricted to authorized networks",
                "master_authorized_networks_config not set"))
    return findings
