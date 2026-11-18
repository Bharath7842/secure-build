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
            run_as_non_root = sc.get("runAsNonRoot")
            run_as_user = sc.get("runAsUser")
            if run_as_non_root is not True and (run_as_user is None or int(run_as_user) == 0):
                findings.append({
                    "resource": resource.get("id"),
                    "resource_type": resource.get("type"),
                    "message": f"Container '{container.get('name', 'unknown')}' in '{resource.get('name')}' may run as root",
                    "evidence": f"runAsNonRoot={run_as_non_root}, runAsUser={run_as_user}",
                    "line_start": loc.get("line_start"),
                })
    return findings
