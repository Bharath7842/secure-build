from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit

RDS_TYPES = ["aws_db_instance", "aws_rds_cluster"]


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, RDS_TYPES):
        a = attrs(res)
        if a.get("publicly_accessible") is True:
            findings.append(hit(res,
                f"RDS {res.get('type')} is publicly accessible",
                "publicly_accessible = true"))
    return findings
