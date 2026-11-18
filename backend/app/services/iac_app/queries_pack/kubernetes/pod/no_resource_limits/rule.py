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
            resources_block = container.get("resources") or {}
            limits = resources_block.get("limits") or {}
            if not limits or not (limits.get("cpu") and limits.get("memory")):
                findings.append({
                    "resource": resource.get("id"),
                    "resource_type": resource.get("type"),
                    "message": f"Container '{container.get('name')}' in {resource.get('name')} has no CPU/memory limits",
                    "evidence": "resources.limits.cpu or resources.limits.memory not set",
                    "line_start": loc.get("line_start"),
                })
    return findings
