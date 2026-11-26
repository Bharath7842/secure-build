from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_guardduty_detector"]):
        a = attrs(res)
        enabled = a.get("enable", True)
        if str(enabled).lower() not in ("true", "1"):
            findings.append(hit(res,
                f"GuardDuty detector '{res.get('name')}' is not enabled",
                f"enable={enabled!r}"))
    return findings
