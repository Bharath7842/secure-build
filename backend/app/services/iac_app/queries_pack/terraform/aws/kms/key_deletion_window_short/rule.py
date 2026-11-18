from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_kms_key"]):
        a = attrs(res)
        window = a.get("deletion_window_in_days")
        if window is not None and int(window) < 7:
            findings.append(hit(res,
                "KMS key deletion window is less than 7 days",
                f"deletion_window_in_days={window}"))
    return findings
