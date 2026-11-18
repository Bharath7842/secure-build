READ_VERBS = {"get", "list", "watch", "*"}


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
            resources = rule.get("resources") or []
            verbs = set(rule.get("verbs") or [])
            if ("secrets" in resources or "*" in resources) and verbs & READ_VERBS:
                findings.append({
                    "resource": resource.get("id"),
                    "resource_type": resource.get("type"),
                    "message": f"RBAC {resource.get('type')} '{resource.get('name')}' allows reading Secrets",
                    "evidence": f"resources={resources}, verbs={list(verbs)}",
                    "line_start": loc.get("line_start"),
                })
                break
    return findings
