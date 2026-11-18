from app.services.iac_app.scanner.queries.helpers import check_false


def evaluate(document: dict) -> list[dict]:
    return check_false(
        document,
        ["aws_cloudtrail"],
        ["include_global_service_events"],
        "CloudTrail trail does not log global service events",
        missing_is_fail=True,
    )
