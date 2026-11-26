from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit

POD_KINDS = {
    "Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet",
    "Job", "CronJob", "ReplicationController",
}


def _get_pod_spec(resource: dict) -> dict:
    kind = resource.get("type", "")
    a = attrs(resource)
    if kind == "Pod":
        return a.get("spec") or {}
    template = a.get("spec", {}) or {}
    if kind == "CronJob":
        job_template = template.get("jobTemplate", {}) or {}
        job_spec = job_template.get("spec", {}) or {}
        template = job_spec.get("template", {}) or {}
        return template.get("spec", {}) or {}
    template = template.get("template", {}) or {}
    return template.get("spec", {}) or {}


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in (document.get("resources") or []):
        if res.get("type") not in POD_KINDS:
            continue
        pod_spec = _get_pod_spec(res)
        sec_ctx = pod_spec.get("securityContext")
        if not sec_ctx:
            findings.append(hit(res,
                f"{res.get('type')} '{res.get('name')}' does not have a pod-level security context",
                "spec.securityContext is not defined"))
    return findings
