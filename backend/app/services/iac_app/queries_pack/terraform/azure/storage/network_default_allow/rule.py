from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["azurerm_storage_account"]):
        a = attrs(res)
        net_rules = get_nested(a, "network_rules")
        if isinstance(net_rules, list):
            net_rules = net_rules[0] if net_rules else {}
        if not isinstance(net_rules, dict):
            findings.append(hit(res,
                "Azure Storage account has no network rules (default_action is Allow)",
                "network_rules not configured"))
            continue
        default_action = str(net_rules.get("default_action") or "Allow").title()
        if default_action != "Deny":
            findings.append(hit(res,
                "Azure Storage account network rules default action is Allow (not Deny)",
                f"network_rules.default_action={default_action}"))
    return findings
