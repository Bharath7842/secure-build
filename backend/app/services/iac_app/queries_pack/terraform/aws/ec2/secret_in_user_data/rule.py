import re
from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit

_SECRET_RE = re.compile(
    r'(?i)(password|passwd|secret|api[_\-]?key|access[_\-]?key|private[_\-]?key|token|credential)'
    r'\s*[=:]\s*["\']?[A-Za-z0-9/+@#$%^&*!_\-]{8,}',
)


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_instance", "aws_launch_template", "aws_launch_configuration"]):
        a = attrs(res)
        user_data = str(a.get("user_data") or a.get("user_data_base64") or "")
        if not user_data:
            continue
        match = _SECRET_RE.search(user_data)
        if match:
            snippet = user_data[max(0, match.start() - 20):match.end() + 20]
            findings.append(hit(res,
                f"EC2 resource '{res.get('name')}' user_data appears to contain a hardcoded secret",
                f"Pattern match near: ...{snippet[:80]}..."))
    return findings
