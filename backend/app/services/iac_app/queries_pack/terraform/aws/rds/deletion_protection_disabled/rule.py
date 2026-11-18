from app.services.iac_app.scanner.queries.helpers import check_false


def evaluate(document: dict) -> list[dict]:
    return check_false(
        document,
        ["aws_db_instance", "aws_rds_cluster"],
        ["deletion_protection"],
        "RDS deletion protection is disabled",
        missing_is_fail=True,
    )
