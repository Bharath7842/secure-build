def evaluate(document: dict) -> list[dict]:
    findings = []
    for resource in document.get("resources") or []:
        if resource.get("type") not in ("AWS::RDS::DBInstance", "AWS::RDS::DBCluster"):
            continue
        attrs = resource.get("attributes") or {}
        if attrs.get("PubliclyAccessible") is True:
            loc = resource.get("location") or {}
            findings.append({
                "resource": resource.get("id"),
                "resource_type": resource.get("type"),
                "message": f"RDS instance '{resource.get('name')}' is publicly accessible",
                "evidence": "PubliclyAccessible: true",
                "line_start": loc.get("line_start"),
            })
    return findings
