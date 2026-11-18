from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_dynamodb_table"]):
        a = attrs(res)
        sse = get_nested(a, "server_side_encryption")
        if isinstance(sse, list):
            sse = sse[0] if sse else {}
        if not isinstance(sse, dict) or not sse.get("enabled"):
            findings.append(hit(res,
                "DynamoDB table does not have server-side encryption explicitly enabled",
                "server_side_encryption.enabled=false or not set"))
    return findings
