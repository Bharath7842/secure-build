from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_instance"]):
        a = attrs(res)
        meta_opts = get_nested(a, "metadata_options")
        if isinstance(meta_opts, list):
            meta_opts = meta_opts[0] if meta_opts else {}
        if not isinstance(meta_opts, dict):
            meta_opts = {}
        tokens = str(meta_opts.get("http_tokens", "optional")).lower()
        if tokens != "required":
            findings.append(hit(res,
                "EC2 instance does not enforce IMDSv2 (http_tokens != required)",
                f"metadata_options.http_tokens={tokens or 'not set'}"))
    return findings
