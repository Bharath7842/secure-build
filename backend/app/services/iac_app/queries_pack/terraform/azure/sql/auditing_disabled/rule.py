from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    all_resources = document.get("resources") or []
    server_ids = set()
    for res in resources_of(document, ["azurerm_mssql_server", "azurerm_sql_server"]):
        server_ids.add(res.get("id") or res.get("name") or "")

    audited_server_ids = set()
    for res in all_resources:
        if res.get("type") in ("azurerm_mssql_server_extended_auditing_policy", "azurerm_sql_server_extended_auditing_policy"):
            a = attrs(res)
            sid = a.get("server_id") or a.get("sql_server_id") or ""
            audited_server_ids.add(sid)

    findings = []
    for res in resources_of(document, ["azurerm_mssql_server", "azurerm_sql_server"]):
        res_id = res.get("id") or res.get("name") or ""
        if not any(res_id in sid or sid in res_id for sid in audited_server_ids):
            findings.append(hit(res,
                "Azure SQL Server has no extended auditing policy configured",
                "no azurerm_mssql_server_extended_auditing_policy linked"))
    return findings
