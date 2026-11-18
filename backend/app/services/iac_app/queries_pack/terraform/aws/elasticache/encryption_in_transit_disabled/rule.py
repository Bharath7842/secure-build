from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_elasticache_replication_group"]):
        a = attrs(res)
        if not a.get("transit_encryption_enabled"):
            findings.append(hit(res,
                "ElastiCache replication group does not have in-transit (TLS) encryption enabled",
                "transit_encryption_enabled=false or not set"))
    return findings
