from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["azurerm_mssql_firewall_rule", "azurerm_sql_firewall_rule"]):
        a = attrs(res)
        start = str(a.get("start_ip_address") or "")
        end = str(a.get("end_ip_address") or "")
        if start == "0.0.0.0" and end in ("0.0.0.0", "255.255.255.255"):
            findings.append(hit(res,
                "Azure SQL firewall rule allows all Azure service IPs (0.0.0.0–0.0.0.0)",
                f"start_ip={start} end_ip={end}"))
    return findings
