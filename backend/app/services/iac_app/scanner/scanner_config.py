"""Scanner configuration for comprehensive IaC security scanning.

All scanners run as Python libraries — no external binaries or Docker required.
"""

DEFAULT_SCANNERS = ["internal", "secrets"]

SCANNER_CONFIG = {
    "internal": {
        "enabled": True,
        "description": "Built-in query engine with 152 rules covering 11 IaC types — sourced from CIS Benchmarks (AWS, GCP, Azure, K8s, Docker) and NIST 800-53",
        "policy_source": "CIS Benchmarks v3.0 (AWS), v1.8 (K8s), v1.6 (Docker), CIS Azure/GCP + NIST 800-53",
        "policy_count": "152",
        "security_categories": [
            "SECURITY_MISCONFIGURATION",
            "SECRETS",
            "ENCRYPTION",
            "IAM",
            "NETWORK",
            "CONTAINER",
            "KUBERNETES",
            "STORAGE",
            "DATABASE",
            "COMPUTE",
            "SUPPLY_CHAIN",
            "LOGGING",
            "CONTAINER_SECURITY",
            "KEY_MANAGEMENT",
        ],
    },
    "secrets": {
        "enabled": True,
        "description": "Built-in secret detection (regex + entropy), always available",
        "policy_source": "Internal secret pattern library",
        "policy_count": "20+",
        "security_categories": ["SECRETS"],
    },
}


def get_scanner_config(scanner_name: str) -> dict:
    """Get configuration for a specific scanner."""
    return SCANNER_CONFIG.get(scanner_name, {})


def get_enabled_scanners() -> list[str]:
    """Get list of enabled scanners."""
    enabled = [
        name
        for name, config in SCANNER_CONFIG.items()
        if config.get("enabled", False)
    ]
    return enabled or list(DEFAULT_SCANNERS)


def get_security_categories() -> list[str]:
    """Get all security categories that will be scanned."""
    categories = set()
    for config in SCANNER_CONFIG.values():
        if config.get("enabled", False):
            categories.update(config.get("security_categories", []))
    return sorted(list(categories))


def get_scanner_info() -> dict:
    """Get information about all scanners."""
    info = {}
    for name, config in SCANNER_CONFIG.items():
        info[name] = {
            "enabled": config.get("enabled", False),
            "description": config.get("description", ""),
            "policy_source": config.get("policy_source", ""),
            "policy_count": config.get("policy_count", "Built-in"),
            "security_categories": config.get("security_categories", []),
        }
    return info
