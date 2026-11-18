def evaluate(document: dict) -> list[dict]:
    findings = []
    for resource in document.get("resources") or []:
        if resource.get("type") != "ClusterRoleBinding":
            continue
        attrs = resource.get("attributes") or {}
        # roleRef is at the top level of the YAML, stored in raw spec
        spec = attrs.get("spec") or {}
        role_ref = spec.get("roleRef") or attrs.get("roleRef") or {}
        if not isinstance(role_ref, dict):
            role_ref = {}
        if role_ref.get("name") == "cluster-admin":
            loc = resource.get("location") or {}
            findings.append({
                "resource": resource.get("id"),
                "resource_type": resource.get("type"),
                "message": f"ClusterRoleBinding '{resource.get('name')}' grants cluster-admin privileges",
                "evidence": f"roleRef.name=cluster-admin",
                "line_start": loc.get("line_start"),
            })
    return findings
