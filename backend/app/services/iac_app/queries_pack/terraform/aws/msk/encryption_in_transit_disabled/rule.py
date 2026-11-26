from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_msk_cluster"]):
        a = attrs(res)
        enc_info = a.get("encryption_info") or []
        if isinstance(enc_info, list):
            enc_info = enc_info[0] if enc_info else {}
        enc_transit = enc_info.get("encryption_in_transit") or []
        if isinstance(enc_transit, list):
            enc_transit = enc_transit[0] if enc_transit else {}
        client_broker = enc_transit.get("client_broker", "TLS")
        in_cluster = enc_transit.get("in_cluster", True)
        if str(client_broker).upper() != "TLS" or str(in_cluster).lower() not in ("true", "1"):
            findings.append(hit(res,
                f"MSK cluster '{res.get('name')}' does not enforce TLS encryption in transit",
                f"client_broker={client_broker!r}, in_cluster={in_cluster!r}"))
    return findings
