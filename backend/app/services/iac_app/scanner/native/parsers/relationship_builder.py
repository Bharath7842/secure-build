"""Cross-resource relationship analyzer.

Discovers relationships between IaC resources by analyzing references
between them. Examples:
- Security group → EC2 instance (via vpc_security_group_ids)
- IAM role → Lambda function (via role attribute)
- Subnet → EC2 instance (via subnet_id)
- VPC → Security group (via vpc_id)
- KMS key → S3 bucket (via kms_master_key_id)

Matches KICS/Trivy cross-resource analysis capabilities.
"""

from __future__ import annotations

from typing import Any


# Mapping of (source_type, attribute_name) → (target_type_pattern, relationship_name)
_RELATIONSHIP_RULES: list[tuple[str, str, str, str]] = [
    # AWS EC2 → Security Groups
    ("aws_instance", "vpc_security_group_ids", "aws_security_group", "uses_security_group"),
    ("aws_instance", "subnet_id", "aws_subnet", "in_subnet"),
    ("aws_instance", "iam_instance_profile", "aws_iam_instance_profile", "has_instance_profile"),
    ("aws_instance", "key_name", "aws_key_pair", "uses_key_pair"),
    # AWS ELB/ALB
    ("aws_elb", "subnets", "aws_subnet", "in_subnet"),
    ("aws_elb", "security_groups", "aws_security_group", "uses_security_group"),
    ("aws_lb", "subnets", "aws_subnet", "in_subnet"),
    ("aws_lb", "security_groups", "aws_security_group", "uses_security_group"),
    ("aws_alb", "subnets", "aws_subnet", "in_subnet"),
    ("aws_alb", "security_groups", "aws_security_group", "uses_security_group"),
    # AWS Lambda
    ("aws_lambda_function", "role", "aws_iam_role", "assumes_role"),
    ("aws_lambda_function", "vpc_config.security_group_ids", "aws_security_group", "uses_security_group"),
    ("aws_lambda_function", "vpc_config.subnet_ids", "aws_subnet", "in_subnet"),
    # AWS RDS
    ("aws_db_instance", "vpc_security_group_ids", "aws_security_group", "uses_security_group"),
    ("aws_db_instance", "db_subnet_group_name", "aws_db_subnet_group", "in_subnet_group"),
    ("aws_db_instance", "kms_key_id", "aws_kms_key", "encrypted_by"),
    ("aws_db_instance", "monitoring_role_arn", "aws_iam_role", "has_monitoring_role"),
    # AWS S3
    ("aws_s3_bucket", "kms_key_id", "aws_kms_key", "encrypted_by"),
    # AWS EBS
    ("aws_ebs_volume", "kms_key_id", "aws_kms_key", "encrypted_by"),
    # AWS EFS
    ("aws_efs_file_system", "kms_key_id", "aws_kms_key", "encrypted_by"),
    # AWS ElastiCache
    ("aws_elasticache_cluster", "security_group_ids", "aws_security_group", "uses_security_group"),
    # AWS Redshift
    ("aws_redshift_cluster", "vpc_security_group_ids", "aws_security_group", "uses_security_group"),
    # AWS EKS
    ("aws_eks_cluster", "role_arn", "aws_iam_role", "assumes_role"),
    ("aws_eks_cluster", "vpc_config.subnet_ids", "aws_subnet", "in_subnet"),
    ("aws_eks_cluster", "vpc_config.security_group_ids", "aws_security_group", "uses_security_group"),
    ("aws_eks_node_group", "node_role_arn", "aws_iam_role", "assumes_role"),
    # AWS ECS
    ("aws_ecs_task_definition", "execution_role_arn", "aws_iam_role", "has_execution_role"),
    ("aws_ecs_task_definition", "task_role_arn", "aws_iam_role", "has_task_role"),
    ("aws_ecs_service", "cluster", "aws_ecs_cluster", "in_cluster"),
    # AWS CodePipeline
    ("aws_codepipeline", "role_arn", "aws_iam_role", "assumes_role"),
    # AWS CloudWatch
    ("aws_cloudwatch_metric_alarm", "alarm_actions", "aws_sns_topic", "notifies_topic"),
    # AWS API Gateway
    ("aws_api_gateway_rest_api", "endpoint_configuration.types", "aws_vpc_endpoint", "uses_endpoint"),
    # VPC → Subnet
    ("aws_subnet", "vpc_id", "aws_vpc", "in_vpc"),
    ("aws_security_group", "vpc_id", "aws_vpc", "in_vpc"),
    ("aws_network_acl", "vpc_id", "aws_vpc", "in_vpc"),
    ("aws_route_table", "vpc_id", "aws_vpc", "in_vpc"),
    ("aws_flow_log", "vpc_id", "aws_vpc", "logs_vpc"),
    # GCP
    ("google_compute_instance", "network_interface.network", "google_compute_network", "in_network"),
    ("google_compute_instance", "network_interface.subnetwork", "google_compute_subnetwork", "in_subnetwork"),
    ("google_compute_instance", "network_interface.access_config nat_ip", "google_compute_address", "uses_address"),
    ("google_container_cluster", "network", "google_compute_network", "in_network"),
    ("google_container_cluster", "subnetwork", "google_compute_subnetwork", "in_subnetwork"),
    ("google_container_node_pool", "cluster", "google_container_cluster", "in_cluster"),
    # Azure
    ("azurerm_virtual_machine", "network_interface_ids", "azurerm_network_interface", "has_nic"),
    ("azurerm_virtual_machine", "storage_os_disk.kms_key", "azurerm_key_vault_key", "encrypted_by"),
    ("azurerm_linux_virtual_machine", "network_interface_ids", "azurerm_network_interface", "has_nic"),
    ("azurerm_windows_virtual_machine", "network_interface_ids", "azurerm_network_interface", "has_nic"),
    ("azurerm_network_interface", "ip_configuration.subnet_id", "azurerm_subnet", "in_subnet"),
    ("azurerm_kubernetes_cluster", "network_profile.network_plugin", "azurerm_virtual_network", "in_vnet"),
    ("azurerm_mssql_server", "network_rules.virtual_network_subnet_ids", "azurerm_subnet", "in_subnet"),
]

# Pre-computed lookup: source_type → list of (attr, target_pattern, rel_name)
_REL_LOOKUP: dict[str, list[tuple[str, str, str]]] = {}
for src, attr, tgt, rel in _RELATIONSHIP_RULES:
    _REL_LOOKUP.setdefault(src, []).append((attr, tgt, rel))


def _extract_nested_attr(attrs: dict[str, Any], dotted: str) -> Any | None:
    """Extract a potentially nested attribute like 'vpc_config.security_group_ids'."""
    parts = dotted.split(".")
    obj: Any = attrs
    for part in parts:
        if isinstance(obj, dict):
            obj = obj.get(part) or obj.get(f'"{part}"')
            if obj is None:
                return None
        else:
            return None
    return obj


def _normalize_ref(value: Any) -> str | None:
    """Normalize a Terraform reference like 'aws_security_group.sg.id' to 'aws_security_group.sg'."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if value.startswith("var.") or value.startswith("local.") or value.startswith("data."):
        return None
    if value.startswith("${"):
        inner = value[2:-1] if value.endswith("}") else value[2:]
        if "." in inner:
            parts = inner.split(".")
            if len(parts) >= 2:
                return f"{parts[0]}.{parts[1]}"
        return None
    if "." in value:
        parts = value.split(".")
        if len(parts) >= 2:
            return f"{parts[0]}.{parts[1]}"
    return None


def analyze_relationships(resources: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Analyze cross-resource relationships.
    
    Args:
        resources: List of resource dicts with 'id', 'type', 'name', 'config' keys.
        
    Returns:
        Dict mapping resource IDs to lists of related resource IDs with relationship type.
        Format: {"resource_id": ["relationship:related_resource_id", ...]}
    """
    relationships: dict[str, list[str]] = {}

    for res in resources:
        res_type = res.get("type", "")
        res_id = res.get("id", "")
        config = res.get("config") or {}
        attrs = config if isinstance(config, dict) else {}

        if res_type not in _REL_LOOKUP:
            continue

        for attr_name, target_pattern, rel_name in _REL_LOOKUP[res_type]:
            value = _extract_nested_attr(attrs, attr_name)
            if value is None:
                continue

            if isinstance(value, list):
                for item in value:
                    ref = _normalize_ref(item)
                    if ref and ref.startswith(target_pattern):
                        rel_key = f"{rel_name}:{ref}"
                        relationships.setdefault(res_id, []).append(rel_key)
            elif isinstance(value, str):
                ref = _normalize_ref(value)
                if ref and ref.startswith(target_pattern):
                    rel_key = f"{rel_name}:{ref}"
                    relationships.setdefault(res_id, []).append(rel_key)

    return relationships


def get_related_resources(
    resource_id: str,
    relationships: dict[str, list[str]],
    rel_name: str | None = None,
) -> list[str]:
    """Get related resource IDs for a given resource.
    
    Args:
        resource_id: The resource ID to look up.
        relationships: The relationships dict from analyze_relationships().
        rel_name: Optional filter by relationship name.
        
    Returns:
        List of related resource IDs.
    """
    rels = relationships.get(resource_id, [])
    result = []
    for rel in rels:
        parts = rel.split(":", 1)
        if len(parts) == 2:
            name, target = parts
            if rel_name is None or name == rel_name:
                result.append(target)
    return result


def get_resources_using_security_group(
    sg_id: str,
    resources: list[dict[str, Any]],
    relationships: dict[str, list[str]],
) -> list[dict[str, Any]]:
    """Find all resources that use a given security group.
    
    This is a common cross-resource query for security analysis.
    """
    result = []
    for res in resources:
        res_id = res.get("id", "")
        rels = relationships.get(res_id, [])
        for rel in rels:
            if rel.startswith("uses_security_group:") and sg_id in rel:
                result.append(res)
                break
    return result


def get_security_groups_for_resource(
    resource_id: str,
    resources: list[dict[str, Any]],
    relationships: dict[str, list[str]],
) -> list[dict[str, Any]]:
    """Find all security groups attached to a given resource."""
    sg_refs = get_related_resources(resource_id, relationships, "uses_security_group")
    result = []
    for res in resources:
        if res.get("id") in sg_refs:
            result.append(res)
    return result
