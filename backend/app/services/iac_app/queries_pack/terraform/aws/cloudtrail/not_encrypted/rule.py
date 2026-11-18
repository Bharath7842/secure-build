from app.services.iac_app.scanner.queries.helpers import check_missing


def evaluate(document: dict) -> list[dict]:
    return check_missing(
        document,
        ["aws_cloudtrail"],
        "kms_key_id",
        "CloudTrail logs are not encrypted with a KMS key",
    )
