POD_KINDS = {"Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob"}


def evaluate(document: dict) -> list[dict]:
    findings = []
    for resource in document.get("resources") or []:
        if resource.get("type") not in POD_KINDS:
            continue
        a = resource.get("attributes") or {}
        containers = a.get("containers") or []
        loc = resource.get("location") or {}
        for container in containers:
            if not isinstance(container, dict):
                continue
            sc = container.get("securityContext") or {}
            if not sc.get("readOnlyRootFilesystem"):
                findings.append({
                    "resource": resource.get("id"),
                    "resource_type": resource.get("type"),
                    "message": f"Container '{container.get('name', 'unknown')}' in '{resource.get('name')}' has a writable root filesystem",
                    "evidence": "readOnlyRootFilesystem=false or not set",
                    "line_start": loc.get("line_start"),
                })
    return findings
