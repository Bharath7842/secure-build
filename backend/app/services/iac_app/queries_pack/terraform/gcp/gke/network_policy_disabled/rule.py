from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["google_container_cluster"]):
        a = attrs(res)
        network_policy = get_nested(a, "network_policy")
        if isinstance(network_policy, list):
            network_policy = network_policy[0] if network_policy else {}
        if not isinstance(network_policy, dict) or not network_policy.get("enabled"):
            findings.append(hit(res,
                "GKE cluster does not have a network policy enabled",
                "network_policy.enabled=false or not set"))
    return findings
