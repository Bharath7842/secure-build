from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["compose_service"]):
        a = attrs(res)
        cap_add = a.get("cap_add") or []
        if isinstance(cap_add, list) and any(str(c).upper() == "ALL" for c in cap_add):
            findings.append(hit(res,
                f"Docker Compose service '{res.get('name')}' adds ALL Linux capabilities",
                "cap_add contains ALL"))
    return findings
