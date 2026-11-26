from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_glue_job"]):
        a = attrs(res)
        sec_cfg = a.get("security_configuration")
        if not sec_cfg:
            findings.append(hit(res,
                f"Glue job '{res.get('name')}' does not have a security configuration",
                "security_configuration is not set"))
    return findings
