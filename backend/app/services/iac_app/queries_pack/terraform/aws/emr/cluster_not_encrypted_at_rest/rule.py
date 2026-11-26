import json
from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_emr_security_configuration"]):
        a = attrs(res)
        config_str = a.get("configuration", "{}")
        try:
            config = json.loads(config_str) if isinstance(config_str, str) else config_str
        except (json.JSONDecodeError, TypeError):
            continue
        enc_config = config.get("EncryptionConfiguration", {})
        at_rest = enc_config.get("AtRestEncryptionConfiguration", {})
        s3_enc = at_rest.get("S3EncryptionConfiguration", {})
        local_enc = at_rest.get("LocalDiskEncryptionConfiguration", {})
        if not s3_enc and not local_enc:
            findings.append(hit(res,
                f"EMR security configuration '{res.get('name')}' does not have at-rest encryption configured",
                "EncryptionConfiguration.AtRestEncryptionConfiguration is missing"))
    return findings
