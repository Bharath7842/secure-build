from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested

INSECURE_PROTOCOLS = {"sslv3", "tlsv1", "tlsv1_2016", "tlsv1.1_2016"}


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_cloudfront_distribution"]):
        a = attrs(res)
        cert = get_nested(a, "viewer_certificate")
        if isinstance(cert, list):
            cert = cert[0] if cert else {}
        if not isinstance(cert, dict):
            continue
        min_proto = str(cert.get("minimum_protocol_version") or "TLSv1").lower().replace("-", "_")
        if any(min_proto.startswith(p) for p in INSECURE_PROTOCOLS):
            findings.append(hit(res,
                f"CloudFront minimum TLS protocol version is insecure: {min_proto}",
                f"viewer_certificate.minimum_protocol_version={min_proto}"))
    return findings
