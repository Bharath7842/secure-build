def evaluate(document: dict) -> list[dict]:
    findings = []
    for resource in document.get("resources") or []:
        if resource.get("type") != "Dockerfile":
            continue
        attrs = resource.get("attributes") or {}
        healthcheck = attrs.get("healthcheck")
        loc = resource.get("location") or {}
        if not healthcheck:
            findings.append({
                "resource": resource.get("id"),
                "resource_type": resource.get("type"),
                "message": "Dockerfile does not define a HEALTHCHECK instruction",
                "evidence": "HEALTHCHECK not found",
                "line_start": loc.get("line_start"),
            })
    return findings
