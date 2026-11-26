from app.services.iac_app.scanner.queries.helpers import hit


def evaluate(document: dict) -> list[dict]:
    resources = document.get("resources") or []
    # Check if any NetworkPolicy with ingress rules exists
    has_ingress_policy = False
    for res in resources:
        if res.get("type") != "NetworkPolicy":
            continue
        spec = (res.get("attributes") or {}).get("spec") or {}
        policy_types = spec.get("policyTypes") or []
        ingress = spec.get("ingress")
        if "Ingress" in policy_types or ingress is not None:
            has_ingress_policy = True
            break

    if not has_ingress_policy:
        # Only report if there are workload resources that need protection
        workload_kinds = {"Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet"}
        for res in resources:
            if res.get("type") in workload_kinds:
                return [hit(res,
                    f"No NetworkPolicy restricting ingress is defined for workloads in this manifest",
                    "No NetworkPolicy resource with ingress rules found")]
    return []
