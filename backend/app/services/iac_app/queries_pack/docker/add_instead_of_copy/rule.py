def evaluate(document: dict) -> list[dict]:
    findings = []
    for resource in document.get("resources") or []:
        if resource.get("type") != "Dockerfile":
            continue
        attrs = resource.get("attributes") or {}
        instructions = attrs.get("instructions") or []
        for inst in instructions:
            if not isinstance(inst, dict):
                continue
            if inst.get("instruction", "").upper() == "ADD":
                value = inst.get("value", "")
                # Only flag ADD when it looks like a local copy (not a URL or tar)
                if not (value.startswith("http://") or value.startswith("https://")):
                    findings.append({
                        "resource": resource.get("id"),
                        "resource_type": resource.get("type"),
                        "message": "Dockerfile uses ADD for local file — prefer COPY",
                        "evidence": f"ADD {value[:80]}",
                        "line_start": inst.get("startline"),
                    })
    return findings
