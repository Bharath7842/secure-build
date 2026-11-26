import re
from app.services.iac_app.scanner.queries.helpers import hit

_UPGRADE_RE = re.compile(r'\bapt-get\s+(dist-upgrade|upgrade)\b')


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in (document.get("resources") or []):
        if res.get("type") != "Dockerfile":
            continue
        for instruction in (res.get("attributes", {}).get("instructions") or []):
            if not isinstance(instruction, dict):
                continue
            cmd = str(instruction.get("cmd", "")).upper()
            value = str(instruction.get("value") or instruction.get("original") or "")
            if cmd == "RUN" and _UPGRADE_RE.search(value):
                findings.append(hit(res,
                    "Dockerfile uses apt-get upgrade/dist-upgrade making builds non-reproducible",
                    f"RUN instruction: {value[:120]}"))
    return findings
