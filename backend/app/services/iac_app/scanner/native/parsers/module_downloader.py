"""Terraform module downloader — handles registry, git, and HTTP module sources."""

from __future__ import annotations

import json
import logging
import re
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Any
from urllib.request import urlopen, Request
from urllib.error import URLError

logger = logging.getLogger(__name__)

_REGISTRY_API = "https://registry.terraform.io/v1/modules"


def classify_source(source: str) -> str:
    """Classify a module source string into its type.

    Returns: 'local', 'registry', 'git', 'github', 'http', or 'unknown'
    """
    if not source:
        return "unknown"
    s = source.strip()
    if s.startswith("./") or s.startswith("../") or s.startswith("/"):
        return "local"
    if s.startswith("git::") or s.startswith("hg::"):
        return "git"
    if s.startswith("github.com/") or s.startswith("git@github.com:"):
        return "github"
    if s.startswith("http://") or s.startswith("https://"):
        return "http"
    if s.startswith("s3::") or s.startswith("gcs::"):
        return "cloud"
    parts = s.split("/")
    if len(parts) == 3 and all(p.replace("-", "").replace("_", "").isalnum() for p in parts):
        return "registry"
    if len(parts) == 4 and parts[0].count(".") > 0:
        return "registry"
    return "unknown"


def parse_registry_source(source: str) -> dict[str, str]:
    """Parse a registry module source into components.

    Format: [hostname/]namespace/name/provider
    """
    parts = source.strip().split("/")
    hostname = "registry.terraform.io"
    if len(parts) == 4 and parts[0].count(".") > 0:
        hostname = parts[0]
        parts = parts[1:]
    if len(parts) == 3:
        return {"hostname": hostname, "namespace": parts[0], "name": parts[1], "provider": parts[2]}
    return {}


def download_registry_module(
    namespace: str,
    name: str,
    provider: str,
    version: str | None = None,
    hostname: str = "registry.terraform.io",
    cache_dir: str | None = None,
) -> Path | None:
    """Download a module from the Terraform Registry.

    Returns the path to the downloaded module directory, or None on failure.
    """
    cache_base = Path(cache_dir) if cache_dir else Path(tempfile.mkdtemp(prefix="tf_modules_"))
    module_cache = cache_base / f"{namespace}--{name}--{provider}"
    if module_cache.exists():
        return module_cache

    try:
        version_path = f"{namespace}/{name}/{provider}"
        versions_url = f"https://{hostname}/v1/modules/{version_path}/versions"
        req = Request(versions_url, headers={"Accept": "application/json"})
        with urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        versions = data.get("modules", [{}])[0].get("versions", [])
        if not versions:
            logger.warning("No versions found for module %s", version_path)
            return None

        if version:
            resolved = _resolve_version(version, [v.get("version", "") for v in versions])
        else:
            resolved = versions[0].get("version", "")

        if not resolved:
            logger.warning("Could not resolve version %r for %s", version, version_path)
            return None

        download_url = f"https://{hostname}/v1/modules/{version_path}/{resolved}/download"
        req = Request(download_url, headers={"Accept": "application/json"})
        with urlopen(req, timeout=10) as resp:
            download_info = json.loads(resp.read().decode())

        archive_url = download_info.get("download_url")
        if not archive_url:
            logger.warning("No download URL for %s v%s", version_path, resolved)
            return None

        module_cache.mkdir(parents=True, exist_ok=True)
        req = Request(archive_url)
        with urlopen(req, timeout=30) as resp:
            archive_data = resp.read()

        archive_path = module_cache / "module.zip"
        archive_path.write_bytes(archive_data)

        with zipfile.ZipFile(archive_path) as zf:
            zf.extractall(module_cache)

        archive_path.unlink(missing_ok=True)
        subdirs = [d for d in module_cache.iterdir() if d.is_dir()]
        if len(subdirs) == 1 and subdirs[0].name != "modules":
            inner = subdirs[0]
            for item in inner.iterdir():
                shutil.move(str(item), str(module_cache / item.name))
            inner.rmdir()

        logger.info("Downloaded module %s v%s to %s", version_path, resolved, module_cache)
        return module_cache

    except (URLError, json.JSONDecodeError, OSError, zipfile.BadZipFile) as exc:
        logger.warning("Failed to download registry module %s/%s/%s: %s", namespace, name, provider, exc)
        return None


def _resolve_version(constraint: str, available: list[str]) -> str | None:
    """Resolve a version constraint against available versions."""
    if not constraint or not available:
        return available[0] if available else None

    constraint = constraint.strip()
    if constraint.startswith("~>"):
        prefix = constraint[2:].strip()
        parts = prefix.split(".")
        if len(parts) >= 2:
            upper = list(parts[:-1])
            upper[-1] = str(int(upper[-1]) + 1)
            upper_bound = ".".join(upper)
            candidates = [v for v in available if v >= prefix and v < upper_bound]
        else:
            candidates = [v for v in available if v.startswith(prefix)]
        return candidates[0] if candidates else None

    if constraint.startswith(">="):
        min_ver = constraint[2:].strip()
        candidates = [v for v in available if v >= min_ver]
        return candidates[0] if candidates else None

    if constraint.startswith("="):
        exact = constraint[1:].strip()
        return exact if exact in available else None

    if constraint in available:
        return constraint

    return available[0] if available else None


def download_git_module(source: str, cache_dir: str | None = None) -> Path | None:
    """Download a module from a git repository."""
    cache_base = Path(cache_dir) if cache_dir else Path(tempfile.mkdtemp(prefix="tf_git_"))
    module_cache = cache_base / "git_module"
    if module_cache.exists():
        return module_cache

    try:
        import subprocess
        url = source
        ref = None
        subpath = None

        if "//" in source:
            parts = source.split("//")
            url = parts[0]
            remainder = parts[1] if len(parts) > 1 else ""
            if "@" in url:
                url, ref = url.rsplit("@", 1)
            if remainder:
                subpath = remainder

        module_cache.mkdir(parents=True, exist_ok=True)
        cmd = ["git", "clone", "--depth", "1"]
        if ref:
            cmd.extend(["--branch", ref])
        cmd.extend([url, str(module_cache / "repo")])
        subprocess.run(cmd, capture_output=True, timeout=60)

        repo_dir = module_cache / "repo"
        if subpath:
            target = repo_dir / subpath
            if target.exists():
                for item in target.iterdir():
                    shutil.move(str(item), str(module_cache / item.name))
        else:
            for item in repo_dir.iterdir():
                if item.name != ".git":
                    shutil.move(str(item), str(module_cache / item.name))

        shutil.rmtree(repo_dir, ignore_errors=True)
        return module_cache

    except Exception as exc:
        logger.warning("Failed to download git module %s: %s", source, exc)
        return None


def resolve_module_path(
    source: str,
    caller_file: str,
    version: str | None = None,
    cache_dir: str | None = None,
    skip_remote: bool = False,
) -> Path | None:
    """Resolve a module source to a local filesystem path.

    Handles local paths, registry modules, git sources, and GitHub sources.
    When skip_remote=True, returns None for any non-local module source.
    """
    source_type = classify_source(source)

    if source_type == "local":
        caller_dir = Path(caller_file).parent if caller_file else Path.cwd()
        module_path = caller_dir / source
        if module_path.exists() and module_path.is_dir():
            return module_path
        return None

    if skip_remote:
        logger.debug("Skipping remote module download: %s", source)
        return None

    if source_type == "registry":
        parsed = parse_registry_source(source)
        if parsed:
            return download_registry_module(
                namespace=parsed["namespace"],
                name=parsed["name"],
                provider=parsed["provider"],
                version=version,
                hostname=parsed["hostname"],
                cache_dir=cache_dir,
            )
        return None

    if source_type in ("git", "github"):
        if source_type == "github" and not source.startswith("git::"):
            source = f"git::https://{source}"
        return download_git_module(source, cache_dir=cache_dir)

    if source_type == "http":
        return _download_http_module(source, cache_dir=cache_dir)

    return None


def _download_http_module(source: str, cache_dir: str | None = None) -> Path | None:
    """Download a module from an HTTP/HTTPS URL."""
    cache_base = Path(cache_dir) if cache_dir else Path(tempfile.mkdtemp(prefix="tf_http_"))
    module_cache = cache_base / "http_module"
    if module_cache.exists():
        return module_cache

    try:
        module_cache.mkdir(parents=True, exist_ok=True)
        req = Request(source)
        with urlopen(req, timeout=30) as resp:
            data = resp.read()

        if source.endswith(".zip") or resp.headers.get("Content-Type", "").startswith("application/zip"):
            archive_path = module_cache / "module.zip"
            archive_path.write_bytes(data)
            with zipfile.ZipFile(archive_path) as zf:
                zf.extractall(module_cache)
            archive_path.unlink(missing_ok=True)
        else:
            (module_cache / "main.tf").write_bytes(data)

        return module_cache

    except Exception as exc:
        logger.warning("Failed to download HTTP module %s: %s", source, exc)
        return None
