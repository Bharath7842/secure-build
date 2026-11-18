from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["google_compute_instance"]):
        a = attrs(res)
        metadata = a.get("metadata") or {}
        if not isinstance(metadata, dict):
            metadata = {}
        os_login = str(metadata.get("enable-oslogin") or "").strip().upper()
        if os_login not in ("TRUE", "true", "1"):
            findings.append(hit(res,
                "GCE instance does not have OS Login enabled",
                f"metadata.enable-oslogin={os_login or 'not set'}"))
    return findings
