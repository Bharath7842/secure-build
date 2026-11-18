def evaluate(document: dict) -> list[dict]:
    findings = []
    for resource in document.get("resources") or []:
        if resource.get("type") not in ("ClusterRole", "Role"):
            continue
        attrs = resource.get("attributes") or {}
        spec = attrs.get("spec") or {}
        # rules are at top-level in YAML
        rules = spec.get("rules") or attrs.get("rules") or []
        loc = resource.get("location") or {}
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            if "*" in (rule.get("verbs") or []):
                findings.append({
                    "resource": resource.get("id"),
                    "resource_type": resource.get("type"),
                    "message": f"RBAC {resource.get('type')} '{resource.get('name')}' grants wildcard verb (*)",
                    "evidence": f"verbs contains *",
                    "line_start": loc.get("line_start"),
                })
                break
    return findings
