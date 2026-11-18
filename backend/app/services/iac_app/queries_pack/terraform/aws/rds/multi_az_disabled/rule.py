from app.services.iac_app.scanner.queries.helpers import check_false


def evaluate(document: dict) -> list[dict]:
    return check_false(
        document,
        ["aws_db_instance"],
        ["multi_az"],
        "RDS instance does not have Multi-AZ enabled",
        missing_is_fail=True,
    )
