from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_dynamodb_table"]):
        a = attrs(res)
        pitr = get_nested(a, "point_in_time_recovery")
        if isinstance(pitr, list):
            pitr = pitr[0] if pitr else {}
        if not isinstance(pitr, dict) or not pitr.get("enabled"):
            findings.append(hit(res,
                "DynamoDB table does not have point-in-time recovery enabled",
                "point_in_time_recovery.enabled=false or not set"))
    return findings
