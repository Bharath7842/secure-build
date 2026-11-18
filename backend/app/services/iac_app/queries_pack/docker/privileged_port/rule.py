def evaluate(document: dict) -> list[dict]:
    findings = []
    for resource in document.get("resources") or []:
        if resource.get("type") != "Dockerfile":
            continue
        attrs = resource.get("attributes") or {}
        exposed_ports = attrs.get("exposed_ports") or []
        loc = resource.get("location") or {}
        for port_entry in exposed_ports:
            try:
                port = int(str(port_entry).split("/")[0])
            except (ValueError, TypeError):
                continue
            if port < 1024:
                findings.append({
                    "resource": resource.get("id"),
                    "resource_type": resource.get("type"),
                    "message": f"Dockerfile exposes privileged port {port} (< 1024)",
                    "evidence": f"EXPOSE {port_entry}",
                    "line_start": loc.get("line_start"),
                })
    return findings
