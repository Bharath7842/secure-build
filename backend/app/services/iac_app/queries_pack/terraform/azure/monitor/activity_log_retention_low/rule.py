from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["azurerm_monitor_log_profile"]):
        a = attrs(res)
        retention = get_nested(a, "retention_policy")
        if isinstance(retention, list):
            retention = retention[0] if retention else {}
        if not isinstance(retention, dict) or not retention.get("enabled"):
            findings.append(hit(res,
                "Azure Monitor log profile does not have retention enabled",
                "retention_policy.enabled=false or not set"))
            continue
        days = int(retention.get("days") or 0)
        if days < 365:
            findings.append(hit(res,
                f"Azure Monitor log profile retains logs for only {days} days (minimum 365)",
                f"retention_policy.days={days}"))
    return findings
