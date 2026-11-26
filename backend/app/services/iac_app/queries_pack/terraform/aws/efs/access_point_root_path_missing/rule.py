from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_efs_access_point"]):
        a = attrs(res)
        root_dir = a.get("root_directory") or []
        if isinstance(root_dir, list):
            root_dir = root_dir[0] if root_dir else {}
        path = root_dir.get("path", "/") if isinstance(root_dir, dict) else "/"
        if not path or path == "/":
            findings.append(hit(res,
                f"EFS access point '{res.get('name')}' does not enforce a non-root directory path",
                f"root_directory.path={path!r}"))
    return findings
