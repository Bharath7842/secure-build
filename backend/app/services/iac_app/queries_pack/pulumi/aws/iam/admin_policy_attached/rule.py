from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws:iam/rolePolicyAttachment:RolePolicyAttachment", "aws:iam/userPolicyAttachment:UserPolicyAttachment", "aws:iam/groupPolicyAttachment:GroupPolicyAttachment"]):
        a = attrs(res)
        policy_arn = str(a.get("policyArn") or "")
        if "AdministratorAccess" in policy_arn:
            findings.append(hit(res,
                "Pulumi IAM entity has the AdministratorAccess policy attached",
                f"policyArn={policy_arn}"))
    return findings
