POD_KINDS = {"Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob"}


def evaluate(document: dict) -> list[dict]:
    findings = []
    for resource in document.get("resources") or []:
        if resource.get("type") not in POD_KINDS:
            continue
        attrs = resource.get("attributes") or {}
        pod_spec = attrs.get("pod_spec") or {}
        if pod_spec.get("hostPID") is True:
            loc = resource.get("location") or {}
            findings.append({
                "resource": resource.get("id"),
                "resource_type": resource.get("type"),
                "message": f"Pod '{resource.get('name')}' shares host PID namespace (hostPID: true)",
                "evidence": "hostPID: true",
                "line_start": loc.get("line_start"),
            })
    return findings
