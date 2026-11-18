def evaluate(document: dict) -> list[dict]:
    findings = []
    for resource in document.get("resources") or []:
        if resource.get("type") != "AWS::IAM::AccountPasswordPolicy":
            continue
        attrs = resource.get("attributes") or {}
        issues = []
        length = attrs.get("MinimumPasswordLength")
        if length is None or int(length) < 14:
            issues.append(f"MinimumPasswordLength={length} (need >= 14)")
        for flag in ["RequireUppercaseCharacters", "RequireLowercaseCharacters", "RequireNumbers", "RequireSymbols"]:
            if not attrs.get(flag):
                issues.append(f"{flag} not true")
        if issues:
            loc = resource.get("location") or {}
            findings.append({
                "resource": resource.get("id"),
                "resource_type": resource.get("type"),
                "message": "CloudFormation IAM password policy does not meet strength requirements",
                "evidence": "; ".join(issues),
                "line_start": loc.get("line_start"),
            })
    return findings
