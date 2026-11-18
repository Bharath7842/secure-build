from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["GRPCService", "ProtoFile"]):
        a = attrs(res)
        syntax = str(a.get("syntax") or "").lower().strip('"').strip("'")
        if syntax == "proto2":
            findings.append(hit(res,
                "gRPC proto file uses deprecated proto2 syntax",
                "syntax=proto2"))
    return findings
