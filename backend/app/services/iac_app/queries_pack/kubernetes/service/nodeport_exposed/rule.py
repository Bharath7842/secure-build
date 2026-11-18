def evaluate(document: dict) -> list[dict]:
    findings = []
    for resource in document.get("resources") or []:
        if resource.get("type") != "Service":
            continue
        attrs = resource.get("attributes") or {}
        spec = attrs.get("spec") or {}
        svc_type = spec.get("type") or ""
        if svc_type == "NodePort":
            loc = resource.get("location") or {}
            findings.append({
                "resource": resource.get("id"),
                "resource_type": resource.get("type"),
                "message": f"Service '{resource.get('name')}' is exposed via NodePort",
                "evidence": "spec.type: NodePort",
                "line_start": loc.get("line_start"),
            })
    return findings
