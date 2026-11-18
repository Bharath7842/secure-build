from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_redshift_cluster"]):
        a = attrs(res)
        if a.get("publicly_accessible", True):
            findings.append(hit(res,
                "Redshift cluster is publicly accessible",
                f"publicly_accessible={a.get('publicly_accessible', 'not set (defaults to true)')}"))
    return findings
