import re
from app.services.iac_app.scanner.queries.helpers import hit

_PIP_INSTALL_RE = re.compile(r'\bpip\d*\s+install\b')
_REQUIRE_HASHES_RE = re.compile(r'--require-hashes')


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
            if cmd == "RUN" and _PIP_INSTALL_RE.search(value) and not _REQUIRE_HASHES_RE.search(value):
                findings.append(hit(res,
                    "Dockerfile installs pip packages without --require-hashes",
                    f"RUN instruction: {value[:120]}"))
    return findings
