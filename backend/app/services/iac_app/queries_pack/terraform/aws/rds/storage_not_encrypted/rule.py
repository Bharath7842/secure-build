from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_db_instance"]):
        a = attrs(res)
        if a.get("storage_encrypted") is not True:
            findings.append(hit(res,
                "RDS instance storage is not encrypted at rest",
                f"storage_encrypted={a.get('storage_encrypted', 'not set')}"))
    return findings
