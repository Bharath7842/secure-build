from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_redshift_cluster"]):
        a = attrs(res)
        if not a.get("encrypted"):
            findings.append(hit(res,
                "Redshift cluster does not have encryption enabled",
                "encrypted=false or not set"))
    return findings
