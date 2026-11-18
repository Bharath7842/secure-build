from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["azurerm_storage_account"]):
        a = attrs(res)
        tls = str(a.get("min_tls_version") or "TLS1_0").upper()
        if tls not in ("TLS1_2", "TLS1_3"):
            findings.append(hit(res,
                f"Azure Storage account minimum TLS version is {tls} (should be TLS1_2)",
                f"min_tls_version={tls}"))
    return findings
