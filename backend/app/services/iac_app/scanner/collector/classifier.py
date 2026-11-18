import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def classify_iac_files(files: list[dict]) -> dict:
    classified = {
        "terraform": [],
        "terraform_plan": [],
        "kubernetes": [],
        "docker": [],
        "docker_compose": [],
        "cloudformation": [],
        "arm": [],
        "bicep": [],
        "pulumi": [],
        "github_actions": [],
        "ansible": [],
        "helm": [],
        "unknown": [],
    }

    for file_info in files:
        file_type = _classify_file(file_info)
        file_info["type"] = file_type
        classified[file_type].append(file_info)

    return classified


def _classify_file(file_info: dict) -> str:
    path = file_info["path"]
    extension = file_info.get("extension", "")
    filename = file_info.get("filename", "")

    if extension == ".tfplan" or filename.lower() in {"tfplan.json", "plan.json", "terraform.tfplan.json"}:
        return "terraform_plan"

    if filename.lower().endswith(".tfplan.json"):
        return "terraform_plan"

    if extension == ".bicep":
        return "bicep"

    if _is_github_actions(file_info):
        return "github_actions"

    if extension in (".tf", ".tfvars", ".tf.json"):
        return "terraform"

    if filename.lower() in {
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    } or (filename.lower().startswith("docker-compose") and extension in {".yml", ".yaml"}):
        return "docker_compose"

    if filename in ("Dockerfile",):
        return "docker"

    if filename.lower() == "dockerfile":
        return "docker"

    if filename == "Chart.yaml":
        return "helm"

    if extension in (".yaml", ".yml", ".json"):
        file_path = Path(file_info.get("absolute_path", path))

        if extension == ".json" and _is_terraform_plan_json(file_path):
            return "terraform_plan"

        if _is_arm_template(file_path, extension):
            return "arm"

        if _is_pulumi(file_path):
            return "pulumi"

        if _is_helm_chart(file_path):
            return "helm"

        if _is_ansible_playbook(file_path):
            return "ansible"

        if _is_cloudformation(file_path):
            return "cloudformation"

        if _is_kubernetes_manifest(file_path):
            return "kubernetes"

    if extension in (".yaml", ".yml"):
        file_path = Path(file_info.get("absolute_path", path))

        if _is_pulumi(file_path):
            return "pulumi"

        if _is_helm_values(file_path):
            return "helm"

        if _is_ansible_role(file_info.get("path", "")):
            return "ansible"

        if _is_likely_kubernetes(file_path):
            return "kubernetes"

    return "unknown"


def _is_helm_chart(file_path: Path) -> bool:
    """Detect Helm Chart.yaml files."""
    try:
        if file_path.name == "Chart.yaml":
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(2000)
            return "apiVersion:" in content and ("name:" in content or "version:" in content)
    except OSError:
        pass
    return False


def _is_helm_values(file_path: Path) -> bool:
    """Detect Helm values.yaml files."""
    try:
        if file_path.name in ("values.yaml", "values.yml"):
            return True
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(2000)
        helm_indicators = ["replicaCount:", "image:", "service:", "ingress:", "resources:"]
        return sum(1 for ind in helm_indicators if ind in content) >= 2
    except OSError:
        return False


def _is_ansible_playbook(file_path: Path) -> bool:
    """Detect Ansible playbook files."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(5000)

        ansible_indicators = [
            "- hosts:",
            "  hosts:",
            "  tasks:",
            "  roles:",
            "  gather_facts:",
            "  become:",
            "  vars:",
            "  handlers:",
        ]
        return sum(1 for ind in ansible_indicators if ind in content) >= 2
    except OSError:
        return False


def _is_ansible_role(path: str) -> bool:
    """Detect files in Ansible role directory structure."""
    path_lower = path.lower().replace("\\", "/")
    role_patterns = [
        "/tasks/main.yml",
        "/tasks/main.yaml",
        "/handlers/main.yml",
        "/handlers/main.yaml",
        "/vars/main.yml",
        "/vars/main.yaml",
        "/defaults/main.yml",
        "/defaults/main.yaml",
        "/templates/",
        "/files/",
    ]
    return any(pattern in path_lower for pattern in role_patterns)


def _is_kubernetes_manifest(file_path: Path) -> bool:
    try:
        if file_path.suffix in (".yaml", ".yml"):
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(5000)

            k8s_indicators = [
                "apiVersion:",
                "kind:",
                "metadata:",
                "spec:",
                "containers:",
                "Deployment",
                "Service",
                "ConfigMap",
                "Secret",
                "Pod",
                "StatefulSet",
                "DaemonSet",
                "Ingress",
                "Namespace",
            ]

            indicator_count = sum(
                1 for indicator in k8s_indicators if indicator in content
            )
            return indicator_count >= 2

        elif file_path.suffix == ".json":
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(5000)

            data = json.loads(content)
            if isinstance(data, dict):
                k8s_keys = {"apiVersion", "kind", "metadata", "spec"}
                return len(k8s_keys.intersection(data.keys())) >= 2

    except (json.JSONDecodeError, OSError):
        pass

    return False


def _is_cloudformation(file_path: Path) -> bool:
    try:
        if file_path.suffix == ".json":
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(5000)

            data = json.loads(content)
            if isinstance(data, dict):
                return "AWSTemplateFormatVersion" in data

        if file_path.suffix in (".yaml", ".yml"):
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(5000)

            return "AWSTemplateFormatVersion" in content

    except (json.JSONDecodeError, OSError):
        pass

    return False


def _is_likely_kubernetes(file_path: Path) -> bool:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(5000)

        k8s_keywords = [
            "apiVersion:",
            "kind:",
            "metadata:",
            "spec:",
            "container",
            "service",
            "deployment",
            "namespace",
            "replicas:",
        ]

        score = sum(1 for kw in k8s_keywords if kw.lower() in content.lower())
        return score >= 3

    except OSError:
        return False


def _is_github_actions(file_info: dict) -> bool:
    """Detect GitHub Actions workflow files by path."""
    path_str = file_info.get("path", "").replace("\\", "/").lower()
    if ".github/workflows/" in path_str:
        ext = file_info.get("extension", "").lower()
        return ext in (".yml", ".yaml")
    return False


def _is_arm_template(file_path: Path, extension: str) -> bool:
    """Detect Azure ARM templates by $schema containing deploymentTemplate."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(5000)

        arm_schema_indicators = ["deploymentTemplate", "resourceManagerTemplate"]

        if extension == ".json":
            data = json.loads(content)
            if isinstance(data, dict):
                schema_val = data.get("$schema", "")
                return any(ind in schema_val for ind in arm_schema_indicators)

        if extension in (".yaml", ".yml"):
            return any(ind in content for ind in arm_schema_indicators)

    except (json.JSONDecodeError, OSError):
        pass

    return False


def _is_pulumi(file_path: Path) -> bool:
    """Detect Pulumi YAML programs by top-level 'runtime:' key."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(2000)

        if file_path.suffix in (".yaml", ".yml"):
            lines = content.strip().split("\n")
            for line in lines[:10]:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    if stripped.startswith("runtime:"):
                        return True
                    break

    except OSError:
        pass

    return False


def _is_terraform_plan_json(file_path: Path) -> bool:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
            content = handle.read(4000)
        return '"format_version"' in content and (
            '"planned_values"' in content or '"resource_changes"' in content
        )
    except OSError:
        return False


def _is_terraform_plan_json(file_path: Path) -> bool:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
            content = handle.read(4000)
        return '"format_version"' in content and (
            '"planned_values"' in content or '"resource_changes"' in content
        )
    except OSError:
        return False
