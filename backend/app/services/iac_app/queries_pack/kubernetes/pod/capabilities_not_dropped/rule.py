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
            sc = container.get("securityContext") or {}
            capabilities = sc.get("capabilities") or {}
            dropped = [str(c).upper() for c in (capabilities.get("drop") or [])]
            if "ALL" not in dropped:
                findings.append({
                    "resource": resource.get("id"),
                    "resource_type": resource.get("type"),
                    "message": f"Container '{container.get('name')}' in {resource.get('name')} does not drop all capabilities",
                    "evidence": "securityContext.capabilities.drop does not contain ALL",
                    "line_start": loc.get("line_start"),
                })
    return findings
