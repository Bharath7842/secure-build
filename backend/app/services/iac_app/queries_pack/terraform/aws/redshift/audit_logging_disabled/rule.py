from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_redshift_cluster"]):
        a = attrs(res)
        logging = get_nested(a, "logging")
        if isinstance(logging, list):
            logging = logging[0] if logging else {}
        if not isinstance(logging, dict) or not logging.get("enable"):
            findings.append(hit(res,
                "Redshift cluster does not have audit logging enabled",
                "logging.enable=false or not set"))
    return findings
