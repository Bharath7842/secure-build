from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["compose_service"]):
        a = attrs(res)
        if str(a.get("network_mode") or "").lower() == "host":
            findings.append(hit(res,
                f"Docker Compose service '{res.get('name')}' uses host network mode",
                "network_mode=host"))
    return findings
