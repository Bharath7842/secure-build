import re

CURL_SHELL_PATTERN = re.compile(r"(curl|wget)\s.+\|\s*(ba)?sh", re.IGNORECASE)


def evaluate(document: dict) -> list[dict]:
    findings = []
    for resource in document.get("resources") or []:
        if resource.get("type") != "Dockerfile":
            continue
        attrs = resource.get("attributes") or {}
        for inst in (attrs.get("instructions") or []):
            if not isinstance(inst, dict):
                continue
            if inst.get("instruction", "").upper() != "RUN":
                continue
            value = inst.get("value", "")
            if CURL_SHELL_PATTERN.search(value):
                findings.append({
                    "resource": resource.get("id"),
                    "resource_type": resource.get("type"),
                    "message": "Dockerfile pipes curl/wget directly to a shell — verify script integrity first",
                    "evidence": f"RUN {value[:100]}",
                    "line_start": inst.get("startline"),
                })
    return findings
