from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_efs_file_system"]):
        a = attrs(res)
        encrypted = a.get("encrypted")
        if str(encrypted).lower() not in ("true", "1"):
            findings.append(hit(res,
                f"EFS file system '{res.get('name')}' is not encrypted at rest",
                f"encrypted={encrypted!r}"))
    return findings
