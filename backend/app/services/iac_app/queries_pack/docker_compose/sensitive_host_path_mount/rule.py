from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit

SENSITIVE_PATHS = ("/etc", "/var/run/docker.sock", "/proc", "/sys", "/dev", "/root", "/boot")


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["compose_service"]):
        a = attrs(res)
        volumes = a.get("volumes") or []
        for vol in volumes:
            source = ""
            if isinstance(vol, str):
                source = vol.split(":")[0] if ":" in vol else vol
            elif isinstance(vol, dict):
                source = str(vol.get("source") or vol.get("type") or "")
            if any(source.startswith(sp) for sp in SENSITIVE_PATHS):
                findings.append(hit(res,
                    f"Docker Compose service '{res.get('name')}' mounts sensitive host path '{source}'",
                    f"volume={source}"))
                break
    return findings
