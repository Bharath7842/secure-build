import re

SECRET_PATTERN = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|auth[_-]?key)",
    re.IGNORECASE,
)


def evaluate(document: dict) -> list[dict]:
    findings = []
    for resource in document.get("resources") or []:
        if resource.get("type") != "Dockerfile":
            continue
        attrs = resource.get("attributes") or {}
        if attrs.get("has_secrets_in_env"):
            loc = resource.get("location") or {}
            findings.append({
                "resource": resource.get("id"),
                "resource_type": resource.get("type"),
                "message": "Dockerfile sets a secret-looking value in an ENV instruction",
                "evidence": "ENV instruction contains a key matching password/secret/token/key pattern",
                "line_start": loc.get("line_start"),
            })
            continue
        # Also check instructions directly for ENV with suspicious names
        for inst in (attrs.get("instructions") or []):
            if not isinstance(inst, dict):
                continue
            if inst.get("instruction", "").upper() != "ENV":
                continue
            value = inst.get("value", "")
            key_part = value.split("=")[0].strip()
            if SECRET_PATTERN.search(key_part):
                findings.append({
                    "resource": resource.get("id"),
                    "resource_type": resource.get("type"),
                    "message": "Dockerfile ENV instruction may expose secret in image layer",
                    "evidence": f"ENV {key_part}=...",
                    "line_start": inst.get("startline"),
                })
                break
    return findings
