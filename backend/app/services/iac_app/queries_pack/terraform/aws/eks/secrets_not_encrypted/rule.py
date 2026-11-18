from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_eks_cluster"]):
        a = attrs(res)
        enc_config = a.get("encryption_config")
        if isinstance(enc_config, dict):
            enc_config = [enc_config]
        if not enc_config:
            findings.append(hit(res,
                "EKS cluster Kubernetes secrets are not encrypted with KMS",
                "encryption_config not configured"))
            continue
        has_secrets = any(
            "secrets" in (cfg.get("resources") or [])
            for cfg in enc_config
            if isinstance(cfg, dict)
        )
        if not has_secrets:
            findings.append(hit(res,
                "EKS cluster encryption_config does not include secrets",
                "encryption_config.resources does not contain 'secrets'"))
    return findings
