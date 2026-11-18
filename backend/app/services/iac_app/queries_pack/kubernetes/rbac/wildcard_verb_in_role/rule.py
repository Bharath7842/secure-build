def evaluate(document: dict) -> list[dict]:
    findings = []
    for resource in document.get("resources") or []:
        if resource.get("type") not in ("ClusterRole", "Role"):
            continue
        a = resource.get("attributes") or {}
        spec = a.get("spec") or {}
        rules = spec.get("rules") or []
        loc = resource.get("location") or {}
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            verbs = rule.get("verbs") or []
            if "*" in verbs:
                resources = rule.get("resources") or ["*"]
                findings.append({
                    "resource": resource.get("id"),
                    "resource_type": resource.get("type"),
                    "message": f"{resource.get('type')} '{resource.get('name')}' grants wildcard verb (*) on {resources}",
                    "evidence": f"verbs=['*'] resources={resources}",
                    "line_start": loc.get("line_start"),
                })
                break
    return findings
