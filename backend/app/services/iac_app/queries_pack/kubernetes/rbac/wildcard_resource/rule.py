def evaluate(document: dict) -> list[dict]:
    findings = []
    for resource in document.get("resources") or []:
        if resource.get("type") not in ("ClusterRole", "Role"):
            continue
        attrs = resource.get("attributes") or {}
        spec = attrs.get("spec") or {}
        rules = spec.get("rules") or attrs.get("rules") or []
        loc = resource.get("location") or {}
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            if "*" in (rule.get("resources") or []):
                findings.append({
                    "resource": resource.get("id"),
                    "resource_type": resource.get("type"),
                    "message": f"RBAC {resource.get('type')} '{resource.get('name')}' grants access to all resources (*)",
                    "evidence": "resources contains *",
                    "line_start": loc.get("line_start"),
                })
                break
    return findings
