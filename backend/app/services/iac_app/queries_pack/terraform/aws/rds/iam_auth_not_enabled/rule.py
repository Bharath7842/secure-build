from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_db_instance", "aws_rds_cluster"]):
        a = attrs(res)
        iam_auth = a.get("iam_database_authentication_enabled")
        if str(iam_auth).lower() not in ("true", "1"):
            findings.append(hit(res,
                f"RDS resource '{res.get('name')}' does not have IAM authentication enabled",
                f"iam_database_authentication_enabled={iam_auth!r}"))
    return findings
