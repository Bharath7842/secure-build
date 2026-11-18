from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_db_instance"]):
        a = attrs(res)
        retention = a.get("backup_retention_period")
        if retention is None or int(retention) < 7:
            findings.append(hit(res,
                "RDS backup retention period is less than 7 days",
                f"backup_retention_period={retention}"))
    return findings
