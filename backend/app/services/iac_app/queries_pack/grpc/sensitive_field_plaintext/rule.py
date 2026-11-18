from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit
import re

SENSITIVE_PATTERN = re.compile(r'\b(password|secret|token|api_key|private_key|credential|passwd|auth_token)\b', re.IGNORECASE)


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["GRPCService", "ProtoFile"]):
        a = attrs(res)
        messages = a.get("messages") or []
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            msg_name = msg.get("name") or "unknown"
            for field in (msg.get("fields") or []):
                if not isinstance(field, dict):
                    continue
                field_name = str(field.get("name") or "")
                field_type = str(field.get("type") or "").lower()
                if SENSITIVE_PATTERN.search(field_name) and field_type == "string":
                    findings.append(hit(res,
                        f"gRPC message '{msg_name}' has sensitive field '{field_name}' stored as string",
                        f"message={msg_name} field={field_name} type=string"))
    return findings
