POD_KINDS = {"Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob"}


def evaluate(document: dict) -> list[dict]:
    findings = []
    for resource in document.get("resources") or []:
        if resource.get("type") not in POD_KINDS:
            continue
        attrs = resource.get("attributes") or {}
        pod_spec = attrs.get("pod_spec") or {}
        containers = attrs.get("containers") or []
        loc = resource.get("location") or {}
        # Check pod-level securityContext
        pod_sc = pod_spec.get("securityContext") or {}
        pod_run_as_non_root = pod_sc.get("runAsNonRoot")
        pod_run_as_user = pod_sc.get("runAsUser")
        for container in containers:
            if not isinstance(container, dict):
                continue
            sc = container.get("securityContext") or {}
            run_as_non_root = sc.get("runAsNonRoot")
            run_as_user = sc.get("runAsUser")
            # Fail if neither the container nor the pod enforces non-root
            effective_non_root = run_as_non_root if run_as_non_root is not None else pod_run_as_non_root
            effective_uid = run_as_user if run_as_user is not None else pod_run_as_user
            if effective_non_root is not True and (effective_uid is None or int(effective_uid) == 0):
                findings.append({
                    "resource": resource.get("id"),
                    "resource_type": resource.get("type"),
                    "message": f"Container '{container.get('name')}' in {resource.get('name')} may run as root",
                    "evidence": "runAsNonRoot not set to true and runAsUser not set to non-zero",
                    "line_start": loc.get("line_start"),
                })
    return findings
