POD_KINDS = {"Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob"}


def evaluate(document: dict) -> list[dict]:
    findings = []
    for resource in document.get("resources") or []:
        if resource.get("type") not in POD_KINDS:
            continue
        a = resource.get("attributes") or {}
        pod_spec = a.get("pod_spec") or {}
        loc = resource.get("location") or {}
        automount = pod_spec.get("automountServiceAccountToken")
        if automount is None or automount is True:
            findings.append({
                "resource": resource.get("id"),
                "resource_type": resource.get("type"),
                "message": f"Pod '{resource.get('name')}' automatically mounts service account token",
                "evidence": f"automountServiceAccountToken={automount if automount is not None else 'not set (defaults to true)'}",
                "line_start": loc.get("line_start"),
            })
    return findings
