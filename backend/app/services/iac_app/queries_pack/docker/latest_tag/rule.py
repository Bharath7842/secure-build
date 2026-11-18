def evaluate(document: dict) -> list[dict]:
    findings = []
    for resource in document.get("resources") or []:
        if resource.get("type") != "Dockerfile":
            continue
        attrs = resource.get("attributes") or {}
        base_image = str(attrs.get("base_image") or "").strip()
        loc = resource.get("location") or {}
        if not base_image or base_image.lower() in ("scratch", ""):
            continue
        tag = base_image.split(":")[-1] if ":" in base_image else "latest"
        if "@" not in base_image and (tag == "latest" or ":" not in base_image):
            findings.append({
                "resource": resource.get("id"),
                "resource_type": resource.get("type"),
                "message": f"Dockerfile FROM uses unpinned image '{base_image}'",
                "evidence": f"FROM {base_image}",
                "line_start": loc.get("line_start"),
            })
    return findings
