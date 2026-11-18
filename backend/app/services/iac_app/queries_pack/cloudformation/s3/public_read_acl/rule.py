PUBLIC_ACLS = {"public-read", "public-read-write", "authenticated-read"}


def evaluate(document: dict) -> list[dict]:
    findings = []
    for resource in document.get("resources") or []:
        if resource.get("type") != "AWS::S3::Bucket":
            continue
        attrs = resource.get("attributes") or {}
        acl = str(attrs.get("AccessControl") or "").lower()
        if acl in PUBLIC_ACLS:
            loc = resource.get("location") or {}
            findings.append({
                "resource": resource.get("id"),
                "resource_type": resource.get("type"),
                "message": f"S3 bucket '{resource.get('name')}' has public ACL: {acl}",
                "evidence": f"AccessControl={acl}",
                "line_start": loc.get("line_start"),
            })
    return findings
