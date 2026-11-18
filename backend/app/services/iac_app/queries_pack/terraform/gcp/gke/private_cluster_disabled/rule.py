from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["google_container_cluster"]):
        a = attrs(res)
        private_config = get_nested(a, "private_cluster_config")
        if isinstance(private_config, list):
            private_config = private_config[0] if private_config else {}
        if not isinstance(private_config, dict) or not private_config.get("enable_private_nodes"):
            findings.append(hit(res,
                "GKE cluster is not configured as a private cluster",
                "private_cluster_config.enable_private_nodes=false or not set"))
    return findings
