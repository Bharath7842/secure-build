from app.services.iac_app.scanner.parsers.base import ParserAdapter

__all__ = ["ParserAdapter", "get_parser", "all_parsers"]


def all_parsers() -> list[ParserAdapter]:
    from app.services.iac_app.scanner.native.parsers.terraform_plan_parser import TerraformPlanParser
    from app.services.iac_app.scanner.native.parsers.terraform_parser import TerraformParser
    from app.services.iac_app.scanner.native.parsers.kubernetes_parser import KubernetesParser
    from app.services.iac_app.scanner.native.parsers.dockerfile_parser import DockerfileParser
    from app.services.iac_app.scanner.native.parsers.docker_compose_parser import DockerComposeParser
    from app.services.iac_app.scanner.native.parsers.cloudformation_parser import CloudFormationParser
    from app.services.iac_app.scanner.native.parsers.bicep_parser import BicepParser
    from app.services.iac_app.scanner.native.parsers.helm_parser import HelmParser
    from app.services.iac_app.scanner.native.parsers.pulumi_parser import PulumiParser
    from app.services.iac_app.scanner.native.parsers.openapi_parser import OpenAPIParser
    from app.services.iac_app.scanner.native.parsers.grpc_parser import GRPCParser
    from app.services.iac_app.scanner.native.parsers.sam_parser import SAMParser
    from app.services.iac_app.scanner.native.parsers.cdk_parser import CDKParser
    from app.services.iac_app.scanner.native.parsers.kustomize_parser import KustomizeParser

    return [
        TerraformPlanParser(),
        DockerComposeParser(),
        BicepParser(),
        TerraformParser(),
        DockerfileParser(),
        KubernetesParser(),
        CloudFormationParser(),
        HelmParser(),
        PulumiParser(),
        OpenAPIParser(),
        GRPCParser(),
        SAMParser(),
        CDKParser(),
        KustomizeParser(),
    ]


def get_parser(file_path: str) -> ParserAdapter | None:
    for parser in all_parsers():
        if parser.supports(file_path):
            return parser
    return None
