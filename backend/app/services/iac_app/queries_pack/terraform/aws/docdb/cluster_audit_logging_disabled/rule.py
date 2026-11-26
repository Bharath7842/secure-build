from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_docdb_cluster"]):
        a = attrs(res)
        exports = a.get("enabled_cloudwatch_logs_exports") or []
        if "audit" not in [str(e).lower() for e in exports]:
            findings.append(hit(res,
                f"DocumentDB cluster '{res.get('name')}' does not have audit logging enabled",
                f"enabled_cloudwatch_logs_exports={exports!r}"))
    return findings
