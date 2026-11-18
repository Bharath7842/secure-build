from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["azurerm_kubernetes_cluster"]):
        a = attrs(res)
        rbac = a.get("role_based_access_control_enabled")
        if rbac is False:
            findings.append(hit(res,
                "AKS cluster has RBAC disabled",
                "role_based_access_control_enabled=false"))
    return findings
