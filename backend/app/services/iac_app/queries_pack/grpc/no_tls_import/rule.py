from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit

AUTH_IMPORT_PATTERNS = ("auth", "tls", "ssl", "oauth", "jwt", "credentials")


def evaluate(document: dict) -> list[dict]:
    findings = []
    seen_files = set()
    for res in resources_of(document, ["GRPCService", "ProtoFile"]):
        a = attrs(res)
        file_path = (res.get("location") or {}).get("file_path") or res.get("id") or ""
        if file_path in seen_files:
            continue
        seen_files.add(file_path)
        imports = a.get("imports") or []
        has_auth = any(any(p in str(imp).lower() for p in AUTH_IMPORT_PATTERNS) for imp in imports)
        if not has_auth and imports is not None:
            findings.append(hit(res,
                "gRPC proto file does not import any TLS or authentication package",
                f"imports={imports or 'none'}"))
    return findings
