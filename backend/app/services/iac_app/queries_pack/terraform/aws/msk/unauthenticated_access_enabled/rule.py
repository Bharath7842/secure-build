from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def _has_auth(a: dict) -> bool:
    ca = a.get("client_authentication") or []
    if isinstance(ca, list):
        ca = ca[0] if ca else {}
    if not isinstance(ca, dict):
        return False
    # Check SASL IAM
    sasl = ca.get("sasl") or []
    if isinstance(sasl, list):
        sasl = sasl[0] if sasl else {}
    if isinstance(sasl, dict):
        if str(sasl.get("iam", "")).lower() in ("true", "1"):
            return True
        scram = sasl.get("scram") or []
        if isinstance(scram, list):
            scram = scram[0] if scram else {}
        if isinstance(scram, dict) and str(scram.get("enabled", "")).lower() in ("true", "1"):
            return True
    # Check TLS mutual auth
    tls = ca.get("tls") or []
    if isinstance(tls, list):
        tls = tls[0] if tls else {}
    if isinstance(tls, dict):
        cas = tls.get("certificate_authority_arns") or []
        if cas:
            return True
    return False


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_msk_cluster"]):
        a = attrs(res)
        if not _has_auth(a):
            findings.append(hit(res,
                f"MSK cluster '{res.get('name')}' has no client authentication configured",
                "client_authentication: no IAM, SASL/SCRAM, or TLS configured"))
    return findings
