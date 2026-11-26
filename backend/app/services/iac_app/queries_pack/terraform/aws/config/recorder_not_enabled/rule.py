from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    # Check recorder status resources
    enabled_recorders = set()
    for res in resources_of(document, ["aws_config_configuration_recorder_status"]):
        a = attrs(res)
        is_enabled = a.get("is_enabled", True)
        name = a.get("name", "")
        if str(is_enabled).lower() in ("true", "1") and name:
            enabled_recorders.add(name)

    findings = []
    for res in resources_of(document, ["aws_config_configuration_recorder"]):
        a = attrs(res)
        rec_name = a.get("name", "default")
        recording_group = a.get("recording_group") or []
        if isinstance(recording_group, list):
            recording_group = recording_group[0] if recording_group else {}
        all_supported = recording_group.get("all_supported", True) if isinstance(recording_group, dict) else True
        if str(all_supported).lower() not in ("true", "1") or rec_name not in enabled_recorders:
            findings.append(hit(res,
                f"AWS Config recorder '{rec_name}' is not enabled or not recording all resources",
                f"all_supported={all_supported!r}, recorder_status_enabled={rec_name in enabled_recorders}"))
    return findings
