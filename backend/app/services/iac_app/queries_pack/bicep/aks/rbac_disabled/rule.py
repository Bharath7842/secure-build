from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["Microsoft.ContainerService/managedClusters"]):
        a = attrs(res)
        rbac = a.get("enableRBAC", True)
        if rbac is False:
            findings.append(hit(res,
                "Bicep AKS cluster has RBAC disabled",
                "enableRBAC=false"))
    return findings
