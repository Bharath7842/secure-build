from app.services.iac_app.scanner.queries.helpers import check_false


def evaluate(document: dict) -> list[dict]:
    return check_false(
        document,
        ["aws_cloudtrail"],
        ["is_multi_region_trail"],
        "CloudTrail trail is not multi-region",
        missing_is_fail=True,
    )
