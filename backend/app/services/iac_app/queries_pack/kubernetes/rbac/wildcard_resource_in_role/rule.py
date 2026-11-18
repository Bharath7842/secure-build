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
            resources = rule.get("resources") or []
            verbs = rule.get("verbs") or []
            if "*" in resources and verbs:
                findings.append({
                    "resource": resource.get("id"),
                    "resource_type": resource.get("type"),
                    "message": f"{resource.get('type')} '{resource.get('name')}' grants access to all resource types (*)",
                    "evidence": f"resources=['*'] verbs={verbs}",
                    "line_start": loc.get("line_start"),
                })
                break
    return findings
