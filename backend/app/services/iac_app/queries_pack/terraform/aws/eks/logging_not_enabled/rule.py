from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit

REQUIRED_LOG_TYPES = {"api", "audit", "authenticator", "controllerManager", "scheduler"}


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_eks_cluster"]):
        a = attrs(res)
        enabled = set(a.get("enabled_cluster_log_types") or [])
        missing = REQUIRED_LOG_TYPES - enabled
        if missing:
            findings.append(hit(res,
                "EKS cluster is missing control plane log types",
                f"missing log types: {', '.join(sorted(missing))}"))
    return findings
