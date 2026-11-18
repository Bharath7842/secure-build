from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit

FLAGS = [
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
]


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_s3_bucket_public_access_block"]):
        a = attrs(res)
        failing = [f for f in FLAGS if a.get(f) is not True]
        if failing:
            findings.append(hit(res,
                "S3 public access block is incomplete",
                ", ".join(failing) + " not set to true"))
    return findings
