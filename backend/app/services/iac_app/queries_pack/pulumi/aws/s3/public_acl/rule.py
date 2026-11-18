from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit

PUBLIC_ACLS = {"public-read", "public-read-write", "authenticated-read"}


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws:s3/bucket:Bucket", "aws:s3:Bucket"]):
        a = attrs(res)
        acl = str(a.get("acl") or "private").lower()
        if acl in PUBLIC_ACLS:
            findings.append(hit(res,
                f"Pulumi S3 bucket has a public ACL: {acl}",
                f"acl={acl}"))
    return findings
