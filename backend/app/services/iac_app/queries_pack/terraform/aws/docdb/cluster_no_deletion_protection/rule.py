from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_docdb_cluster"]):
        a = attrs(res)
        protection = a.get("deletion_protection")
        if str(protection).lower() not in ("true", "1"):
            findings.append(hit(res,
                f"DocumentDB cluster '{res.get('name')}' has deletion protection disabled",
                f"deletion_protection={protection!r}"))
    return findings
