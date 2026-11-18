from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["azurerm_kubernetes_cluster"]):
        a = attrs(res)
        net_profile = get_nested(a, "network_profile")
        if isinstance(net_profile, list):
            net_profile = net_profile[0] if net_profile else {}
        if not isinstance(net_profile, dict) or not net_profile.get("network_policy"):
            findings.append(hit(res,
                "AKS cluster does not have a network policy configured",
                "network_profile.network_policy not set"))
    return findings
