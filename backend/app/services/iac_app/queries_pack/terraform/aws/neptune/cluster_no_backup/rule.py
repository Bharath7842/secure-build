from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_neptune_cluster"]):
        a = attrs(res)
        retention = a.get("backup_retention_period", 0)
        try:
            if int(retention) < 1:
                findings.append(hit(res,
                    f"Neptune cluster '{res.get('name')}' has no backup retention configured",
                    f"backup_retention_period={retention!r}"))
        except (TypeError, ValueError):
            pass
    return findings
