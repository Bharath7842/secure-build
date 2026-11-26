from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_ecr_repository"]):
        a = attrs(res)
        scan_cfg = a.get("image_scanning_configuration") or []
        if isinstance(scan_cfg, list):
            scan_cfg = scan_cfg[0] if scan_cfg else {}
        scan_on_push = scan_cfg.get("scan_on_push") if isinstance(scan_cfg, dict) else None
        if str(scan_on_push).lower() not in ("true", "1"):
            findings.append(hit(res,
                f"ECR repository '{res.get('name')}' does not have image scanning on push enabled",
                f"image_scanning_configuration.scan_on_push={scan_on_push!r}"))
    return findings
