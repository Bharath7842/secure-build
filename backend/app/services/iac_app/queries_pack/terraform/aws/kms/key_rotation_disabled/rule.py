from app.services.iac_app.scanner.queries.helpers import check_false


def evaluate(document: dict) -> list[dict]:
    return check_false(
        document,
        ["aws_kms_key"],
        ["enable_key_rotation"],
        "KMS key automatic rotation is not enabled",
        missing_is_fail=True,
    )
