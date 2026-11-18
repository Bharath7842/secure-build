"""Kubernetes manifest parser — converts YAML/JSON K8s manifests to ParsedDocument.

Supports RBAC analysis, NetworkPolicy validation, Secret checks, and ServiceAccount analysis.
"""

from __future__ import annotations

import base64
import json
import logging
from pathlib import Path
from typing import Any

import yaml

from app.services.iac_app.domain.document import ParsedDocument
from app.services.iac_app.scanner.parsers.base import ParserAdapter

logger = logging.getLogger(__name__)


class KubernetesParser(ParserAdapter):
    EXTENSIONS = (".yaml", ".yml", ".json")

    def supports(self, file: str) -> bool:
        path = Path(file)
        if path.suffix.lower() not in self.EXTENSIONS:
            return False
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                content = handle.read(4000)
            return "apiVersion" in content and "kind" in content
        except OSError:
            return False

    def parse(self, file: str) -> list[ParsedDocument]:
        path = Path(file)
        documents: list[ParsedDocument] = []
        try:
            for raw in self.parse_file(path):
                documents.append(
                    ParsedDocument(file_path=str(path), iac_type="kubernetes", raw=raw)
                )
        except Exception as exc:
            logger.debug("Failed to parse K8s manifest %s: %s", path, exc)
            documents.append(
                ParsedDocument(
                    file_path=str(path),
                    iac_type="kubernetes",
                    raw={},
                    errors=[str(exc)],
                )
            )
        return documents

    def parse_file(self, file_path: Path) -> list[dict[str, Any]]:
        try:
            suffix = file_path.suffix.lower()
            if suffix == ".json":
                return self._parse_json(file_path)
            return self._parse_yaml(file_path)
        except Exception as exc:
            logger.debug("Failed to parse K8s manifest %s: %s", file_path, exc)
            return []

    def parse_directory(self, dir_path: Path) -> list[dict[str, Any]]:
        results = []
        for ext in ("*.yaml", "*.yml", "*.json"):
            for path in sorted(Path(dir_path).rglob(ext)):
                results.extend(self.parse_file(path))
        return results

    def _parse_yaml(self, file_path: Path) -> list[dict[str, Any]]:
        results = []
        try:
            with open(file_path, "r", encoding="utf-8") as handle:
                docs = list(yaml.safe_load_all(handle))
            for doc in docs:
                if doc and isinstance(doc, dict) and self._is_k8s_resource(doc):
                    results.append(self._normalize(doc, str(file_path)))
        except Exception as exc:
            logger.debug("YAML parse error in %s: %s", file_path, exc)
        return results

    def _parse_json(self, file_path: Path) -> list[dict[str, Any]]:
        results = []
        try:
            with open(file_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data, list):
                for doc in data:
                    if doc and isinstance(doc, dict) and self._is_k8s_resource(doc):
                        results.append(self._normalize(doc, str(file_path)))
            elif isinstance(data, dict) and self._is_k8s_resource(data):
                results.append(self._normalize(data, str(file_path)))
        except Exception as exc:
            logger.debug("JSON parse error in %s: %s", file_path, exc)
        return results

    def _is_k8s_resource(self, doc: dict) -> bool:
        return "apiVersion" in doc and "kind" in doc

    def _pod_spec(self, spec: dict) -> dict:
        if not isinstance(spec, dict):
            return {}
        if "template" in spec and isinstance(spec["template"], dict):
            return spec["template"].get("spec", {}) or {}
        if "jobTemplate" in spec and isinstance(spec["jobTemplate"], dict):
            job_spec = spec["jobTemplate"].get("spec", {}) or {}
            template = job_spec.get("template", {}) if isinstance(job_spec, dict) else {}
            return template.get("spec", {}) or {}
        return spec

    def _normalize(self, doc: dict, file_path: str) -> dict[str, Any]:
        metadata = doc.get("metadata", {}) or {}
        spec = doc.get("spec", {}) or {}
        kind = doc.get("kind", "")
        pod_spec = self._pod_spec(spec)
        containers = []
        if isinstance(pod_spec, dict):
            containers.extend(pod_spec.get("containers") or [])
            containers.extend(pod_spec.get("initContainers") or [])
            containers.extend(pod_spec.get("ephemeralContainers") or [])

        result = {
            "file_path": file_path,
            "api_version": doc.get("apiVersion", ""),
            "kind": kind,
            "metadata": metadata,
            "spec": spec,
            "pod_spec": pod_spec,
            "containers": containers,
            "data": doc.get("data", {}),
            "labels": metadata.get("labels", {}) or {},
            "annotations": metadata.get("annotations", {}) or {},
            "namespace": metadata.get("namespace", "default"),
            "name": metadata.get("name", ""),
        }

        if kind == "Secret":
            result["secret_analysis"] = self._analyze_secret(doc)
        elif kind in ("ClusterRole", "Role"):
            result["rbac_analysis"] = self._analyze_rbac(doc)
        elif kind in ("ClusterRoleBinding", "RoleBinding"):
            result["rbac_binding_analysis"] = self._analyze_rbac_binding(doc)
        elif kind == "NetworkPolicy":
            result["network_policy_analysis"] = self._analyze_network_policy(doc)
        elif kind == "ServiceAccount":
            result["service_account_analysis"] = self._analyze_service_account(doc)

        return result

    def _analyze_secret(self, doc: dict) -> dict[str, Any]:
        data = doc.get("data", {}) or {}
        string_data = doc.get("stringData", {}) or {}
        analysis = {
            "has_data": bool(data),
            "has_string_data": bool(string_data),
            "data_keys": list(data.keys()),
            "string_data_keys": list(string_data.keys()),
            "potentially_plaintext": [],
            "encoding_issues": [],
        }
        for key, value in data.items():
            if isinstance(value, str):
                try:
                    decoded = base64.b64decode(value).decode("utf-8")
                    lower = decoded.lower()
                    if any(word in lower for word in ["password", "secret", "token", "key", "api"]):
                        analysis["potentially_plaintext"].append(key)
                except Exception:
                    analysis["encoding_issues"].append(key)
        for key, value in string_data.items():
            if isinstance(value, str):
                lower = value.lower()
                if any(word in lower for word in ["password", "secret", "token", "key", "api"]):
                    analysis["potentially_plaintext"].append(key)
        return analysis

    def _analyze_rbac(self, doc: dict) -> dict[str, Any]:
        rules = doc.get("rules", []) or doc.get("spec", {}).get("rules", []) or []
        analysis = {
            "rule_count": len(rules),
            "has_wildcard_api_groups": False,
            "has_wildcard_resources": False,
            "has_wildcard_verbs": False,
            "allows_secrets_read": False,
            "allows_all_pods": False,
            "allows_privilege_escalation": False,
            "dangerous_permissions": [],
        }
        for rule in rules:
            api_groups = rule.get("apiGroups", []) or ["*"]
            resources = rule.get("resources", []) or ["*"]
            verbs = rule.get("verbs", []) or ["*"]
            if "*" in api_groups:
                analysis["has_wildcard_api_groups"] = True
            if "*" in resources:
                analysis["has_wildcard_resources"] = True
            if "*" in verbs:
                analysis["has_wildcard_verbs"] = True
            if "secrets" in resources and any(v in ("get", "list", "*") for v in verbs):
                analysis["allows_secrets_read"] = True
            if ("pods" in resources or "*" in resources) and any(v in ("create", "delete", "*") for v in verbs):
                analysis["allows_all_pods"] = True
            if ("pods/exec" in resources or "*" in resources) and any(v in ("create", "*") for v in verbs):
                analysis["allows_privilege_escalation"] = True
                analysis["dangerous_permissions"].append("pods/exec")
        return analysis

    def _analyze_rbac_binding(self, doc: dict) -> dict[str, Any]:
        spec = doc.get("spec", {}) or {}
        subjects = doc.get("subjects", []) or spec.get("subjects", []) or []
        role_ref = doc.get("roleRef", {}) or spec.get("roleRef", {})
        analysis = {
            "binding_kind": doc.get("kind", ""),
            "role_ref": role_ref,
            "subject_count": len(subjects),
            "has_system_service_account": False,
            "has_wildcard_namespace": False,
            "has_cluster_admin": False,
        }
        for subject in subjects:
            name = subject.get("name", "")
            ns = subject.get("namespace", "")
            if name.startswith("system:serviceaccount:") or "kube-system" in ns:
                analysis["has_system_service_account"] = True
            if ns == "*" or ns == "":
                analysis["has_wildcard_namespace"] = True
        if role_ref.get("name") == "cluster-admin":
            analysis["has_cluster_admin"] = True
        return analysis

    def _analyze_network_policy(self, doc: dict) -> dict[str, Any]:
        spec = doc.get("spec", {}) or {}
        pod_selector = spec.get("podSelector", {}) or {}
        policy_types = spec.get("policyTypes", []) or []
        ingress = spec.get("ingress", []) or []
        egress = spec.get("egress", []) or []
        analysis = {
            "policy_types": policy_types,
            "has_default_deny_ingress": False,
            "has_default_deny_egress": False,
            "has_empty_pod_selector": not pod_selector or pod_selector == {},
            "ingress_rule_count": len(ingress),
            "egress_rule_count": len(egress),
            "allows_all_ingress": False,
            "allows_all_egress": False,
        }
        if "Ingress" in policy_types and not ingress:
            analysis["has_default_deny_ingress"] = True
        if "Egress" in policy_types and not egress:
            analysis["has_default_deny_egress"] = True
        for rule in ingress:
            if not rule.get("from"):
                analysis["allows_all_ingress"] = True
        for rule in egress:
            if not rule.get("to"):
                analysis["allows_all_egress"] = True
        return analysis

    def _analyze_service_account(self, doc: dict) -> dict[str, Any]:
        spec = doc.get("spec", {}) or {}
        analysis = {
            "automount_service_account_token": spec.get("automountServiceAccountToken"),
            "has_image_pull_secrets": bool(spec.get("imagePullSecrets")),
            "has_secrets": bool(spec.get("secrets")),
            "secret_count": len(spec.get("secrets", []) or []),
        }
        automount = spec.get("automountServiceAccountToken")
        if automount is None:
            analysis["automount_default"] = True
        return analysis

    def get_containers(self, resource: dict) -> list[dict]:
        if resource.get("containers"):
            return list(resource["containers"])
        spec = resource.get("spec", {}) or {}
        pod_spec = self._pod_spec(spec)
        containers = pod_spec.get("containers", []) if isinstance(pod_spec, dict) else []
        init_containers = pod_spec.get("initContainers", []) if isinstance(pod_spec, dict) else []
        ephemeral_containers = pod_spec.get("ephemeralContainers", []) if isinstance(pod_spec, dict) else []
        return list(containers) + list(init_containers) + list(ephemeral_containers)

    def get_volumes(self, resource: dict) -> list[dict]:
        pod_spec = resource.get("pod_spec") or self._pod_spec(resource.get("spec", {}) or {})
        return pod_spec.get("volumes", []) if isinstance(pod_spec, dict) else []

    def get_security_context(self, resource: dict) -> dict:
        pod_spec = resource.get("pod_spec") or self._pod_spec(resource.get("spec", {}) or {})
        return pod_spec.get("securityContext", {}) if isinstance(pod_spec, dict) else {}
