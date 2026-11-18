from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_ecr_repository"]):
        a = attrs(res)
        scan_config = get_nested(a, "image_scanning_configuration")
        if isinstance(scan_config, list):
            scan_config = scan_config[0] if scan_config else {}
        if not isinstance(scan_config, dict) or not scan_config.get("scan_on_push"):
            findings.append(hit(res,
                "ECR repository does not have image scanning on push enabled",
                "image_scanning_configuration.scan_on_push=false or not set"))
    return findings
