from app.services.iac_app.scanner.queries.helpers import resources_of, attrs, hit


def evaluate(document: dict) -> list[dict]:
    findings = []
    for res in resources_of(document, ["aws_ecr_repository"]):
        a = attrs(res)
        mutability = str(a.get("image_tag_mutability") or "MUTABLE").upper()
        if mutability != "IMMUTABLE":
            findings.append(hit(res,
                "ECR repository allows mutable image tags (image_tag_mutability=MUTABLE)",
                f"image_tag_mutability={mutability}"))
    return findings
