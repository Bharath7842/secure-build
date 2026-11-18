from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["compose_service"]):
        a = attrs(res)
        if a.get("privileged") is True:
            findings.append(hit(res,
                f"Docker Compose service '{res.get('name')}' runs in privileged mode",
                "privileged=true"))
    return findings
