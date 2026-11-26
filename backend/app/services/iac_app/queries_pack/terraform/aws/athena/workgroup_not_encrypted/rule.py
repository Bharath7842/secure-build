from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def _get_block(d, *keys):
    for key in keys:
        if not isinstance(d, dict):
            return {}
        val = d.get(key) or []
        d = val[0] if isinstance(val, list) and val else val if isinstance(val, dict) else {}
    return d if isinstance(d, dict) else {}


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_athena_workgroup"]):
        a = attrs(res)
        config = _get_block(a, "configuration")
        result_cfg = _get_block(config, "result_configuration")
        enc_cfg = _get_block(result_cfg, "encryption_configuration")
        enc_option = enc_cfg.get("encryption_option", "")
        if str(enc_option).upper() not in ("SSE_KMS", "CSE_KMS", "SSE_S3"):
            findings.append(hit(res,
                f"Athena workgroup '{res.get('name')}' does not enforce query result encryption",
                f"encryption_configuration.encryption_option={enc_option!r}"))
    return findings
