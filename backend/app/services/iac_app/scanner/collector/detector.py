"""Deterministic IaC type detection from filename, extension, and content."""

from __future__ import annotations

from pathlib import Path

from app.services.iac_app.domain.document import DetectedFile
from app.services.iac_app.scanner.collector.classifier import classify_iac_files, _classify_file


class IaCDetector:
    """Detect Terraform, Kubernetes, Dockerfile, CloudFormation, Helm, etc.

    Detection is deterministic. It never uses an LLM.
    """

    CONFIDENCE = {
        "terraform": 0.99,
        "terraform_plan": 0.95,
        "docker": 0.99,
        "docker_compose": 0.99,
        "kubernetes": 0.9,
        "cloudformation": 0.9,
        "helm": 0.92,
        "ansible": 0.85,
        "bicep": 0.99,
        "arm": 0.9,
        "pulumi": 0.85,
        "github_actions": 0.95,
        "unknown": 0.1,
    }

    REASONS = {
        "terraform": "Terraform extension (.tf / .tf.json)",
        "terraform_plan": "Terraform plan file (.tfplan or plan JSON)",
        "docker": "Dockerfile filename",
        "docker_compose": "Docker Compose filename",
        "kubernetes": "YAML/JSON with apiVersion and kind",
        "cloudformation": "AWSTemplateFormatVersion or AWS::* resources",
        "helm": "Helm Chart.yaml / values.yaml",
        "ansible": "Ansible playbook or role structure",
        "bicep": "Bicep extension",
        "arm": "Azure ARM deployment template schema",
        "pulumi": "Pulumi YAML runtime declaration",
        "github_actions": "GitHub Actions workflow path",
        "unknown": "No IaC indicators matched",
    }

    def detect(self, files: list[dict]) -> list[DetectedFile]:
        detected: list[DetectedFile] = []
        for file_info in files:
            iac_type = _classify_file(file_info)
            detected.append(
                DetectedFile(
                    path=file_info.get("path", ""),
                    iac_type=iac_type,
                    confidence=self.CONFIDENCE.get(iac_type, 0.1),
                    reason=self.REASONS.get(iac_type, "Content/filename heuristics"),
                    absolute_path=file_info.get("absolute_path", ""),
                    size=int(file_info.get("size") or 0),
                    extension=file_info.get("extension", ""),
                )
            )
        return detected

    def detect_and_classify(self, files: list[dict]) -> tuple[list[DetectedFile], dict]:
        detected = self.detect(files)
        classified = classify_iac_files(files)
        return detected, classified

    def detect_path(self, path: str) -> DetectedFile:
        file_path = Path(path)
        file_info = {
            "path": str(file_path),
            "absolute_path": str(file_path),
            "extension": file_path.suffix.lower(),
            "filename": file_path.name,
            "size": file_path.stat().st_size if file_path.exists() else 0,
        }
        iac_type = _classify_file(file_info)
        return DetectedFile(
            path=str(file_path),
            iac_type=iac_type,
            confidence=self.CONFIDENCE.get(iac_type, 0.1),
            reason=self.REASONS.get(iac_type, "Content/filename heuristics"),
            absolute_path=str(file_path),
            size=int(file_info["size"]),
            extension=file_info["extension"],
        )
