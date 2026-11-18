"""Convert parser output into the canonical normalized document model."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.services.iac_app.domain.document import Location, NormalizedDocument, NormalizedResource, ParsedDocument


PROVIDER_PREFIXES = {
    "aws_": "aws",
    "azurerm_": "azure",
    "google_": "gcp",
    "kubernetes_": "kubernetes",
    "helm_": "helm",
    "docker_": "docker",
}


def _provider_from_type(resource_type: str, iac_type: str) -> str:
    for prefix, provider in PROVIDER_PREFIXES.items():
        if resource_type.startswith(prefix):
            return provider
    if iac_type == "kubernetes":
        return "kubernetes"
    if iac_type == "docker":
        return "docker"
    if iac_type == "cloudformation":
        return "aws"
    if resource_type.startswith("AWS::"):
        return "aws"
    return iac_type


class DocumentNormalizer:
    def normalize(self, parsed: ParsedDocument | dict, iac_type: str | None = None) -> NormalizedDocument:
        if isinstance(parsed, ParsedDocument):
            iac_type = parsed.iac_type
            raw = parsed.raw or {}
            file_path = parsed.file_path
        else:
            payload = parsed or {}
            if "raw" in payload and ("file_path" in payload or "iac_type" in payload):
                raw = payload.get("raw") or {}
                file_path = payload.get("file_path") or raw.get("file_path", "")
                iac_type = iac_type or payload.get("iac_type") or raw.get("iac_type", "unknown")
            else:
                raw = payload
                file_path = raw.get("file_path", "")
                iac_type = iac_type or raw.get("iac_type", "unknown")

        if iac_type in {"terraform", "terraform_plan"}:
            return self._normalize_terraform(file_path, raw)
        if iac_type == "kubernetes":
            return self._normalize_kubernetes(file_path, raw)
        if iac_type == "docker":
            return self._normalize_docker(file_path, raw)
        if iac_type == "docker_compose":
            return self._normalize_docker_compose(file_path, raw)
        if iac_type == "cloudformation":
            return self._normalize_cloudformation(file_path, raw)
        if iac_type == "bicep":
            return self._normalize_bicep(file_path, raw)
        if iac_type in {"sam", "cdk"}:
            return self._normalize_cfn_like(file_path, raw)
        if iac_type == "helm":
            return self._normalize_helm(file_path, raw)
        if iac_type == "pulumi":
            return self._normalize_pulumi(file_path, raw)
        if iac_type == "openapi":
            return self._normalize_openapi(file_path, raw)
        if iac_type == "grpc":
            return self._normalize_grpc(file_path, raw)
        return NormalizedDocument(file=file_path, iac_type=iac_type or "unknown", raw_evidence=raw)

    def normalize_many(self, documents: list[ParsedDocument | dict]) -> list[NormalizedDocument]:
        result = []
        for doc in documents:
            if isinstance(doc, ParsedDocument):
                if doc.errors and not doc.raw:
                    continue
            elif isinstance(doc, dict) and doc.get("errors") and not doc.get("raw"):
                continue
            result.append(self.normalize(doc))
        return result

    def _normalize_terraform(self, file_path: str, raw: dict[str, Any]) -> NormalizedDocument:
        resources = []
        data_source_resources = []
        for resource_id, resource in (raw.get("resources") or {}).items():
            resource_type = resource.get("type", "")
            name = resource.get("name", "")
            src_file = _rel_name(resource.get("file") or file_path)
            resources.append(
                NormalizedResource(
                    id=resource_id,
                    type=resource_type,
                    provider=_provider_from_type(resource_type, "terraform"),
                    name=name,
                    attributes=resource.get("config") or {},
                    location=Location(file_path=src_file or None),
                    raw=resource,
                )
            )
        for ds_id, ds_config in (raw.get("data_sources") or {}).items():
            if isinstance(ds_config, dict):
                parts = ds_id.split(".", 1)
                ds_type = ds_config.get("type") or (parts[0] if len(parts) == 2 else "unknown")
                ds_name = ds_config.get("name") or (parts[1] if len(parts) == 2 else ds_id)
                config = ds_config.get("config") or ds_config
                data_source_resources.append(
                    NormalizedResource(
                        id=f"data.{ds_id}",
                        type=f"data.{ds_type}",
                        provider=_provider_from_type(ds_type, "terraform"),
                        name=ds_name,
                        attributes=config,
                        location=Location(file_path=_rel_name(file_path) or None),
                        raw=ds_config,
                    )
                )
        variables = {}
        for var_name, var_config in (raw.get("variables") or {}).items():
            if isinstance(var_config, dict):
                variables[var_name] = var_config.get("default")
        locals_dict = raw.get("locals") or {}
        return NormalizedDocument(
            file=_rel_name(file_path),
            iac_type="terraform",
            provider="aws" if any(r.provider == "aws" for r in resources) else None,
            resources=resources,
            raw_evidence=raw,
            variables=variables if variables else None,
            locals=locals_dict if locals_dict else None,
            data_sources=data_source_resources if data_source_resources else None,
        )

    def _normalize_kubernetes(self, file_path: str, raw: dict[str, Any]) -> NormalizedDocument:
        kind = raw.get("kind") or "Unknown"
        name = raw.get("name") or (raw.get("metadata") or {}).get("name") or "unnamed"
        resource_id = f"{kind}/{name}"
        attributes = {
            "apiVersion": raw.get("api_version") or raw.get("apiVersion"),
            "kind": kind,
            "metadata": raw.get("metadata") or {},
            "spec": raw.get("spec") or {},
            "pod_spec": raw.get("pod_spec") or {},
            "containers": raw.get("containers") or [],
            "namespace": raw.get("namespace", "default"),
        }
        resource = NormalizedResource(
            id=resource_id,
            type=kind,
            provider="kubernetes",
            name=name,
            attributes=attributes,
            location=Location(file_path=_rel_name(file_path) or None),
            raw=raw,
        )
        return NormalizedDocument(
            file=_rel_name(file_path),
            iac_type="kubernetes",
            provider="kubernetes",
            resources=[resource],
            raw_evidence=raw,
        )

    def _normalize_docker(self, file_path: str, raw: dict[str, Any]) -> NormalizedDocument:
        name = Path(file_path).name if file_path else "Dockerfile"
        resource = NormalizedResource(
            id=name,
            type="Dockerfile",
            provider="docker",
            name=name,
            attributes={
                "base_image": raw.get("base_image"),
                "user": raw.get("user"),
                "instructions": raw.get("instructions") or [],
                "healthcheck": raw.get("healthcheck"),
                "envs": raw.get("envs") or {},
                "exposed_ports": raw.get("exposed_ports") or [],
                "has_secrets_in_env": raw.get("has_secrets_in_env", False),
            },
            location=Location(line_start=1, file_path=_rel_name(file_path) or None),
            raw=raw,
        )
        return NormalizedDocument(
            file=_rel_name(file_path),
            iac_type="docker",
            provider="docker",
            resources=[resource],
            raw_evidence=raw,
        )

    def _normalize_cloudformation(self, file_path: str, raw: dict[str, Any]) -> NormalizedDocument:
        resources = []
        for logical_id, resource in (raw.get("resources") or {}).items():
            resource_type = resource.get("type", "")
            resources.append(
                NormalizedResource(
                    id=logical_id,
                    type=resource_type,
                    provider=_provider_from_type(resource_type, "cloudformation"),
                    name=logical_id,
                    attributes=resource.get("properties") or {},
                    location=Location(file_path=_rel_name(file_path) or None),
                    raw=resource,
                )
            )
        return NormalizedDocument(
            file=_rel_name(file_path),
            iac_type="cloudformation",
            provider="aws",
            resources=resources,
            raw_evidence=raw,
        )

    def _normalize_docker_compose(self, file_path: str, raw: dict[str, Any]) -> NormalizedDocument:
        resources = []
        for name, service in (raw.get("services") or {}).items():
            if not isinstance(service, dict):
                service = {"image": service}
            resources.append(
                NormalizedResource(
                    id=f"service.{name}",
                    type="compose_service",
                    provider="docker",
                    name=name,
                    attributes=service,
                    location=Location(line_start=1, file_path=_rel_name(file_path) or None),
                    raw=service,
                )
            )
        return NormalizedDocument(
            file=_rel_name(file_path),
            iac_type="docker_compose",
            provider="docker",
            resources=resources,
            raw_evidence=raw,
        )

    def _normalize_bicep(self, file_path: str, raw: dict[str, Any]) -> NormalizedDocument:
        resources = []
        for logical_id, resource in (raw.get("resources") or {}).items():
            resource_type = resource.get("type", "")
            resources.append(
                NormalizedResource(
                    id=logical_id,
                    type=resource_type,
                    provider="azure",
                    name=resource.get("name") or logical_id,
                    attributes=resource.get("properties") or {},
                    location=Location(file_path=_rel_name(file_path) or None),
                    raw=resource,
                )
            )
        return NormalizedDocument(
            file=_rel_name(file_path),
            iac_type="bicep",
            provider="azure",
            resources=resources,
            raw_evidence=raw,
        )


    def _normalize_cfn_like(self, file_path: str, raw: dict[str, Any]) -> NormalizedDocument:
        """SAM and CDK are CloudFormation supersets — normalize to cloudformation so CFN rules apply."""
        resources = []
        for logical_id, resource in (raw.get("resources") or {}).items():
            resource_type = resource.get("type", "")
            resources.append(
                NormalizedResource(
                    id=logical_id,
                    type=resource_type,
                    provider=_provider_from_type(resource_type, "cloudformation"),
                    name=logical_id,
                    attributes=resource.get("properties") or {},
                    location=Location(file_path=_rel_name(file_path) or None),
                    raw=resource,
                )
            )
        return NormalizedDocument(
            file=_rel_name(file_path),
            iac_type="cloudformation",
            provider="aws",
            resources=resources,
            raw_evidence=raw,
        )

    def _normalize_helm(self, file_path: str, raw: dict[str, Any]) -> NormalizedDocument:
        """Helm templates render to Kubernetes-like resources; map to kubernetes iac_type."""
        resources = []
        for res in raw.get("resources") or []:
            raw_type = res.get("type") or ""
            kind = raw_type.replace("helm/", "").capitalize() if raw_type.startswith("helm/") else raw_type
            resources.append(
                NormalizedResource(
                    id=res.get("id") or f"{kind}/{res.get('name', 'unknown')}",
                    type=kind,
                    provider="kubernetes",
                    name=res.get("name") or "unknown",
                    attributes=res.get("attributes") or {},
                    location=Location(
                        file_path=_rel_name(res.get("location", {}).get("file_path") or file_path) or None,
                        line_start=res.get("location", {}).get("line_start"),
                    ),
                    raw=res,
                )
            )
        return NormalizedDocument(
            file=_rel_name(file_path),
            iac_type="kubernetes",
            provider="kubernetes",
            resources=resources,
            raw_evidence=raw,
        )

    def _normalize_pulumi(self, file_path: str, raw: dict[str, Any]) -> NormalizedDocument:
        resources = []
        for name, resource in (raw.get("resources") or {}).items():
            resource_type = resource.get("type") or ""
            provider = resource_type.split(":")[0] if ":" in resource_type else "pulumi"
            resources.append(
                NormalizedResource(
                    id=name,
                    type=resource_type,
                    provider=provider,
                    name=name,
                    attributes=resource.get("properties") or {},
                    location=Location(file_path=_rel_name(file_path) or None),
                    raw=resource,
                )
            )
        return NormalizedDocument(
            file=_rel_name(file_path),
            iac_type="pulumi",
            provider=None,
            resources=resources,
            raw_evidence=raw,
        )

    def _normalize_openapi(self, file_path: str, raw: dict[str, Any]) -> NormalizedDocument:
        name = (raw.get("info") or {}).get("title") or Path(file_path).stem or "api"
        resource = NormalizedResource(
            id=f"openapi:{name}",
            type="OpenAPISpec",
            provider="openapi",
            name=name,
            attributes=raw,
            location=Location(file_path=_rel_name(file_path) or None),
            raw=raw,
        )
        return NormalizedDocument(
            file=_rel_name(file_path),
            iac_type="openapi",
            provider="openapi",
            resources=[resource],
            raw_evidence=raw,
        )

    def _normalize_grpc(self, file_path: str, raw: dict[str, Any]) -> NormalizedDocument:
        resources = []
        for service in (raw.get("services") or []):
            svc_name = service.get("name") or "unknown"
            resources.append(
                NormalizedResource(
                    id=f"grpc:{svc_name}",
                    type="GRPCService",
                    provider="grpc",
                    name=svc_name,
                    attributes={"service": service, "syntax": raw.get("syntax"), "package": raw.get("package"), "imports": raw.get("imports") or [], "messages": raw.get("messages") or []},
                    location=Location(file_path=_rel_name(file_path) or None),
                    raw=service,
                )
            )
        if not resources:
            fname = Path(file_path).name if file_path else "unknown.proto"
            resources.append(
                NormalizedResource(
                    id=f"grpc:{fname}",
                    type="ProtoFile",
                    provider="grpc",
                    name=fname,
                    attributes=raw,
                    location=Location(file_path=_rel_name(file_path) or None),
                    raw=raw,
                )
            )
        return NormalizedDocument(
            file=_rel_name(file_path),
            iac_type="grpc",
            provider="grpc",
            resources=resources,
            raw_evidence=raw,
        )


IAC_PATH_ROOTS = {
    "terraform",
    "tf",
    "k8s",
    "kubernetes",
    "helm",
    "charts",
    "cloudformation",
    "cfn",
    "bicep",
    "pulumi",
    "docker",
    "deploy",
    "infra",
    "infrastructure",
    "modules",
    "cdk",
}


def _rel_name(file_path: str) -> str:
    """Keep repo-relative IaC paths (terraform/aws/s3.tf) instead of the basename only."""
    if not file_path:
        return ""
    p = file_path.replace("\\", "/").strip()
    if p.startswith("file://"):
        p = p[7:]
        if len(p) >= 3 and p[0] == "/" and p[2] == ":":
            p = p[1:]
    parts = [part for part in p.split("/") if part and part != "."]
    if parts and len(parts[0]) == 2 and parts[0][1] == ":":
        parts = parts[1:]
    for index, part in enumerate(parts):
        if part.lower() in IAC_PATH_ROOTS:
            return "/".join(parts[index:])
    return parts[-1] if parts else p
