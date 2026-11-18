"""File collection with ignore rules, size limits, symlink and path safety."""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path
from typing import Optional

from app.services.iac_app.core.config import get_settings

logger = logging.getLogger(__name__)

DEFAULT_IGNORE_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    "target",
    ".terraform",
    "__pycache__",
    ".next",
    ".tox",
}

BINARY_EXTENSIONS = {
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".bin",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
    ".7z",
    ".woff",
    ".woff2",
    ".ttf",
}


class FileCollector:
    """Recursive IaC file discovery with safety limits."""

    def __init__(
        self,
        max_files: int | None = None,
        max_file_size: int | None = None,
        ignore_dirs: set[str] | None = None,
        follow_symlinks: bool = False,
    ) -> None:
        settings = get_settings()
        self.max_files = max_files if max_files is not None else getattr(settings, "SCAN_MAX_FILES", settings.MAX_SCAN_FILES)
        self.max_file_size = max_file_size if max_file_size is not None else settings.MAX_FILE_SIZE
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self.follow_symlinks = follow_symlinks
        self.settings = settings

    def collect(self, target_path: str) -> list[dict]:
        target = Path(target_path).resolve()
        self._validate_path(target)

        files: list[dict] = []
        iac_extensions = set(
            self.settings.TERRAFORM_EXTENSIONS
            + self.settings.KUBERNETES_EXTENSIONS
            + self.settings.CLOUDFORMATION_EXTENSIONS
            + [".bicep", ".tfplan", ".json"]
        )
        docker_filenames = set(self.settings.DOCKER_FILES) | {
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
        }
        helm_filenames = {"Chart.yaml", "values.yaml", "values.yml"}
        ansible_extensions = {".yaml", ".yml"}

        for root, dirs, filenames in os.walk(target, followlinks=self.follow_symlinks):
            dirs[:] = [d for d in dirs if d not in self.ignore_dirs]

            root_path = Path(root)
            if not self.follow_symlinks and root_path.is_symlink():
                continue

            for filename in filenames:
                if len(files) >= self.max_files:
                    logger.warning("Reached max file limit (%s), stopping collection", self.max_files)
                    return files

                filepath = root_path / filename
                if not self._is_safe_file(filepath, target):
                    continue

                try:
                    file_size = filepath.stat().st_size
                except (OSError, PermissionError) as exc:
                    logger.warning("Could not access file %s: %s", filepath, exc)
                    continue

                if file_size > self.max_file_size:
                    continue
                if filepath.suffix.lower() in BINARY_EXTENSIONS:
                    continue

                rel_path = filepath.relative_to(target)
                entry = {
                    "path": str(rel_path).replace("\\", "/"),
                    "absolute_path": str(filepath),
                    "size": file_size,
                    "extension": filepath.suffix.lower(),
                    "filename": filename,
                }

                if filepath.suffix.lower() == ".bicep":
                    files.append(entry)
                elif filepath.suffix.lower() == ".tfplan":
                    files.append(entry)
                elif _is_github_actions_file(rel_path):
                    files.append(entry)
                elif filepath.suffix.lower() in iac_extensions:
                    files.append(entry)
                elif (
                    filename in docker_filenames
                    or filename.lower() == "dockerfile"
                    or filename.lower().endswith(".dockerfile")
                    or filename.lower().startswith("docker-compose")
                ):
                    files.append(entry)
                elif filename in helm_filenames:
                    files.append(entry)
                elif filepath.suffix.lower() in ansible_extensions and _is_in_ansible_dir(rel_path):
                    files.append(entry)

        return files

    def _validate_path(self, target: Path) -> None:
        if not target.exists():
            raise FileNotFoundError(f"Target path does not exist: {target}")
        if not target.is_dir():
            raise ValueError(f"Target path is not a directory: {target}")

        blocked = getattr(self.settings, "BLOCKED_PATHS", []) or []
        resolved = str(target).replace("\\", "/").lower()
        for blocked_path in blocked:
            blocked_norm = blocked_path.replace("\\", "/").lower()
            if resolved == blocked_norm or resolved.startswith(blocked_norm.rstrip("/") + "/"):
                raise PermissionError(f"Scanning blocked path is not allowed: {target}")

    def _is_safe_file(self, filepath: Path, target: Path) -> bool:
        try:
            if filepath.is_symlink():
                if not self.follow_symlinks:
                    return False
                resolved = filepath.resolve()
                target_resolved = target.resolve()
                try:
                    resolved.relative_to(target_resolved)
                except ValueError:
                    logger.warning("Skipping symlink outside workspace: %s", filepath)
                    return False
            mode = filepath.stat().st_mode
            if not stat.S_ISREG(mode):
                return False
        except (OSError, PermissionError):
            return False
        return True


def collect_iac_files(
    target_path: str,
    max_files: int = 1000,
    max_file_size: Optional[int] = None,
) -> list[dict]:
    collector = FileCollector(max_files=max_files, max_file_size=max_file_size)
    return collector.collect(target_path)


def _is_in_ansible_dir(rel_path: Path) -> bool:
    path_str = str(rel_path).lower().replace("\\", "/")
    ansible_patterns = [
        "roles/",
        "tasks/",
        "handlers/",
        "playbooks/",
        "group_vars/",
        "host_vars/",
        "inventories/",
    ]
    return any(pattern in path_str for pattern in ansible_patterns)


def _is_github_actions_file(rel_path: Path) -> bool:
    path_str = str(rel_path).replace("\\", "/")
    path_lower = path_str.lower()
    if ".github/workflows/" in path_lower:
        suffix = rel_path.suffix.lower()
        return suffix in (".yml", ".yaml")
    return False
