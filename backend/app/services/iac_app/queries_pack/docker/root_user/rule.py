import re

ROOT_PATTERNS = re.compile(r"^(root|0)$", re.IGNORECASE)


def evaluate(document: dict) -> list[dict]:
    findings = []
    for resource in document.get("resources") or []:
        if resource.get("type") != "Dockerfile":
            continue
        attrs = resource.get("attributes") or {}
        user = str(attrs.get("user") or "").strip()
        loc = resource.get("location") or {}
        if not user or ROOT_PATTERNS.match(user.split(":")[0].strip()):
            findings.append({
                "resource": resource.get("id"),
                "resource_type": resource.get("type"),
                "message": "Dockerfile runs as root — add a non-root USER instruction",
                "evidence": f"USER={user or 'not set'}",
                "line_start": loc.get("line_start"),
            })
    return findings
