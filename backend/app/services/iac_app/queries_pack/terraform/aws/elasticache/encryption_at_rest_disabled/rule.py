from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_elasticache_replication_group"]):
        a = attrs(res)
        if not a.get("at_rest_encryption_enabled"):
            findings.append(hit(res,
                "ElastiCache replication group does not have encryption at rest enabled",
                "at_rest_encryption_enabled=false or not set"))
    return findings
