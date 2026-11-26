import re
from app.services.iac_app.scanner.queries.helpers import hit

ADMIN_PORTS = {22, 2375, 2376, 3389}
_PORT_RE = re.compile(r'^(\d+)')


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in (document.get("resources") or []):
        if res.get("type") != "Dockerfile":
            continue
        for instruction in (res.get("attributes", {}).get("instructions") or []):
            if not isinstance(instruction, dict):
                continue
            cmd = str(instruction.get("cmd", "")).upper()
            if cmd != "EXPOSE":
                continue
            value = str(instruction.get("value") or instruction.get("original") or "")
            m = _PORT_RE.match(value.strip())
            if m:
                port = int(m.group(1))
                if port in ADMIN_PORTS:
                    findings.append(hit(res,
                        f"Dockerfile exposes administrative port {port}",
                        f"EXPOSE {value.strip()}"))
    return findings
