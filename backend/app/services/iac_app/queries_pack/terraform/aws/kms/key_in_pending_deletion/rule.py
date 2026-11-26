from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_kms_key"]):
        a = attrs(res)
        is_enabled = a.get("is_enabled", True)
        deletion_window = a.get("deletion_window_in_days")
        if str(is_enabled).lower() not in ("true", "1") and deletion_window:
            findings.append(hit(res,
                f"KMS key '{res.get('name')}' is disabled and scheduled for deletion in {deletion_window} days",
                f"is_enabled={is_enabled!r}, deletion_window_in_days={deletion_window!r}"))
    return findings
