from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_cloudwatch_log_group"]):
        a = attrs(res)
        retention = a.get("retention_in_days")
        # 0 means never expire; None/missing also means no retention
        try:
            days = int(retention) if retention is not None else 0
        except (TypeError, ValueError):
            days = 0
        if days == 0:
            findings.append(hit(res,
                f"CloudWatch Log Group '{res.get('name')}' has no retention policy (logs never expire)",
                f"retention_in_days={retention!r}"))
    return findings
