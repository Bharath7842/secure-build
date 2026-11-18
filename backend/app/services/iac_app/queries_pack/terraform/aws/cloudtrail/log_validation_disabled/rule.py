from app.services.iac_app.scanner.queries.helpers import check_false


def evaluate(document: dict) -> list[dict]:
    return check_false(
        document,
        ["aws_cloudtrail"],
        ["enable_log_file_validation"],
        "CloudTrail log file validation is disabled",
        missing_is_fail=True,
    )
