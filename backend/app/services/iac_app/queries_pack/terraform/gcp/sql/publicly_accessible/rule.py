from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["google_sql_database_instance"]):
        a = attrs(res)
        settings = get_nested(a, "settings")
        if isinstance(settings, list):
            settings = settings[0] if settings else {}
        if not isinstance(settings, dict):
            continue
        ip_config = get_nested(settings, "ip_configuration")
        if isinstance(ip_config, list):
            ip_config = ip_config[0] if ip_config else {}
        if not isinstance(ip_config, dict):
            ip_config = {}
        if ip_config.get("ipv4_enabled", True):
            findings.append(hit(res,
                "Cloud SQL instance has a public IPv4 address assigned",
                "settings.ip_configuration.ipv4_enabled=true"))
    return findings
