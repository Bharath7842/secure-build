from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit, get_nested


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_instance"]):
        a = attrs(res)
        root_device = get_nested(a, "root_block_device")
        if isinstance(root_device, list):
            root_device = root_device[0] if root_device else {}
        if not isinstance(root_device, dict):
            root_device = {}
        if root_device.get("encrypted") is not True:
            findings.append(hit(res,
                "EC2 instance root EBS volume is not encrypted",
                f"root_block_device.encrypted={root_device.get('encrypted', 'not set')}"))
    return findings
