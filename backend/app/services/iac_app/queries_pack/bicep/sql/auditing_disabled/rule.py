from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    all_resources = document.get("resources") or []
    audited = set()
    for res in all_resources:
        if "auditingSettings" in (res.get("type") or ""):
            a = attrs(res)
            if str(a.get("state") or "").lower() == "enabled":
                parent = str(res.get("name") or "").split("/")[0]
                audited.add(parent)

    findings = []
    for res in resources_of(document, ["Microsoft.Sql/servers"]):
        name = str(res.get("name") or "")
        if not any(name in a or a in name for a in audited):
            findings.append(hit(res,
                "Bicep SQL Server does not have auditing enabled",
                "no auditingSettings child resource with state=Enabled found"))
    return findings
