from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_glue_data_catalog_encryption_settings"]):
        a = attrs(res)
        enc_settings = a.get("data_catalog_encryption_settings") or []
        if isinstance(enc_settings, list):
            enc_settings = enc_settings[0] if enc_settings else {}
        enc_at_rest = enc_settings.get("encryption_at_rest") or [] if isinstance(enc_settings, dict) else []
        if isinstance(enc_at_rest, list):
            enc_at_rest = enc_at_rest[0] if enc_at_rest else {}
        mode = enc_at_rest.get("catalog_encryption_mode", "DISABLED") if isinstance(enc_at_rest, dict) else "DISABLED"
        if str(mode).upper() == "DISABLED":
            findings.append(hit(res,
                f"Glue data catalog '{res.get('name')}' does not have encryption at rest enabled",
                f"encryption_at_rest.catalog_encryption_mode={mode!r}"))
    return findings
