POD_KINDS = {"Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob"}


def evaluate(document: dict) -> list[dict]:
    findings = []
    for resource in document.get("resources") or []:
        if resource.get("type") not in POD_KINDS:
            continue
        attrs = resource.get("attributes") or {}
        containers = attrs.get("containers") or []
        loc = resource.get("location") or {}
        for container in containers:
            if not isinstance(container, dict):
                continue
            image = container.get("image") or ""
            tag = image.split(":")[-1] if ":" in image else "latest"
            if "@" not in image and (tag == "latest" or ":" not in image):
                findings.append({
                    "resource": resource.get("id"),
                    "resource_type": resource.get("type"),
                    "message": f"Container '{container.get('name')}' uses image '{image}' with unpinned tag",
                    "evidence": f"image={image}",
                    "line_start": loc.get("line_start"),
                })
    return findings
