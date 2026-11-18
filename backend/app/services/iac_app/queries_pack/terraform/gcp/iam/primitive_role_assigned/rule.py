from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit

PRIMITIVE_ROLES = {"roles/owner", "roles/editor"}


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["google_project_iam_member", "google_project_iam_binding"]):
        a = attrs(res)
        role = str(a.get("role") or "").strip()
        if role in PRIMITIVE_ROLES:
            findings.append(hit(res,
                f"GCP project has primitive IAM role '{role}' assigned",
                f"role={role}"))
    return findings
