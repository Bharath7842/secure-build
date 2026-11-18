POD_KINDS = {"Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob"}


def evaluate(document: dict) -> list[dict]:
    findings = []
    for resource in document.get("resources") or []:
        if resource.get("type") not in POD_KINDS:
            continue
        attrs = resource.get("attributes") or {}
        pod_spec = attrs.get("pod_spec") or {}
        volumes = pod_spec.get("volumes") or []
        loc = resource.get("location") or {}
        for volume in volumes:
            if not isinstance(volume, dict):
                continue
            if "hostPath" in volume:
                host_path = volume["hostPath"].get("path", "") if isinstance(volume["hostPath"], dict) else ""
                findings.append({
                    "resource": resource.get("id"),
                    "resource_type": resource.get("type"),
                    "message": f"Pod '{resource.get('name')}' mounts host path volume '{volume.get('name')}'",
                    "evidence": f"hostPath.path={host_path}",
                    "line_start": loc.get("line_start"),
                })
    return findings
