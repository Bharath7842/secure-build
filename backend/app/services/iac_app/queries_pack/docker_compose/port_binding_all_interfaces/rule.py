from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["compose_service"]):
        a = attrs(res)
        ports = a.get("ports") or []
        for port in ports:
            port_str = ""
            if isinstance(port, str):
                port_str = port
            elif isinstance(port, dict):
                host_ip = port.get("host_ip") or ""
                if not host_ip or host_ip in ("0.0.0.0", ""):
                    port_str = str(port.get("published", ""))
            if port_str and not port_str.startswith("127."):
                findings.append(hit(res,
                    f"Docker Compose service '{res.get('name')}' binds a port to all interfaces",
                    f"port={port_str}"))
                break
    return findings
