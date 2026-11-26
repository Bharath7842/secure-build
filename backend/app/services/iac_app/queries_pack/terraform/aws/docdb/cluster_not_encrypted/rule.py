from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_docdb_cluster"]):
        a = attrs(res)
        encrypted = a.get("storage_encrypted")
        if str(encrypted).lower() not in ("true", "1"):
            findings.append(hit(res,
                f"DocumentDB cluster '{res.get('name')}' storage is not encrypted",
                f"storage_encrypted={encrypted!r}"))
    return findings
