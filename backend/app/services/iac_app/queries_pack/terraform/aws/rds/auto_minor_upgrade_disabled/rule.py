from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_db_instance"]):
        a = attrs(res)
        auto_upgrade = a.get("auto_minor_version_upgrade", True)
        if str(auto_upgrade).lower() not in ("true", "1"):
            findings.append(hit(res,
                f"RDS instance '{res.get('name')}' has auto minor version upgrade disabled",
                f"auto_minor_version_upgrade={auto_upgrade!r}"))
    return findings
