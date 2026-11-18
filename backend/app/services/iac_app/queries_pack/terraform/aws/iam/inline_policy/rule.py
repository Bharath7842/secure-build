from app.services.iac_app.scanner.queries.helpers import resources_of, hit

INLINE_TYPES = ["aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"]


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, INLINE_TYPES):
        findings.append(hit(res,
            f"Inline IAM policy detected on {res.get('type')} — prefer managed policies",
            f"resource type={res.get('type')}"))
    return findings
