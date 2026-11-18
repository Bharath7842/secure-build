from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    all_resources = document.get("resources") or []
    rotated = set()
    for res in all_resources:
        if res.get("type") == "aws_secretsmanager_secret_rotation":
            a = attrs(res)
            sid = str(a.get("secret_id") or "")
            rotated.add(sid)

    findings = []
    for res in resources_of(document, ["aws_secretsmanager_secret"]):
        res_id = res.get("id") or res.get("name") or ""
        if not any(res_id in r or r in res_id for r in rotated):
            findings.append(hit(res,
                "Secrets Manager secret does not have automatic rotation configured",
                "no aws_secretsmanager_secret_rotation resource linked"))
    return findings
