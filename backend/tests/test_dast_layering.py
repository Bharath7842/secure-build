"""Layering rules for `app/dast/` (DAST-00-020), enforced as an AST walk over imports.

Rules, from architecture.md "Dependency rules":

1. `app/dast/domain/` imports only the standard library and itself. No FastAPI,
   SQLAlchemy, Playwright, httpx, LangChain/LLM SDKs, and nothing else in `app/`.
2. `app/dast/nodes/` never imports `app.routers` or concrete infrastructure
   (services, DB session, browser/model/cloud SDKs). Imports under
   `if TYPE_CHECKING:` are typing-only and ignored.
"""

from __future__ import annotations

import ast
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
DOMAIN_DIR = BACKEND / "app" / "dast" / "domain"
NODES_DIR = BACKEND / "app" / "dast" / "nodes"

DOMAIN_PACKAGE = "app.dast.domain"
EXPECTED_DOMAIN_MODULES = {
    "entities",
    "interfaces",
    "verdict",
    "guardrail",
    "dedupe",
    "diff",
    "detectors",
    "validation",
    "policy",
    "redaction",
    "detector_patterns",
    "mapping",
    "catalog",
    "ruleset",
    "schema",
    "usage",
    "model_errors",
}

# Concrete infrastructure that engine nodes must not reach for directly.
NODE_FORBIDDEN_PREFIXES = (
    "app.routers",
    "app.services",
    "app.db",
    "app.main",
    "playwright",
    "langchain_ollama",
    "langchain_anthropic",
    "langchain_openai",
    "anthropic",
    "openai",
    "boto3",
    "httpx",
    "sqlalchemy",
    "fastapi",
)

# Model SDKs (DAST-02-010): only `app/services/model_gateway/` may import one. SAST has its own LLM
# client and its bridge (`agent_bridge.py`) is outside this rule.
MODEL_SDK_PREFIXES = (
    "langchain_ollama",
    "langchain_anthropic",
    "langchain_openai",
    "anthropic",
    "openai",
    "ollama",
    "boto3",
    "botocore",
)
GATEWAY_DIR = BACKEND / "app" / "services" / "model_gateway"
SDK_RULE_EXEMPT = {BACKEND / "app" / "services" / "agent_bridge.py"}

pytestmark = pytest.mark.unit


def _module_name(path: Path, root: Path) -> str:
    parts = list(path.resolve().relative_to(root.resolve()).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _is_type_checking_test(node: ast.expr) -> bool:
    return (isinstance(node, ast.Name) and node.id == "TYPE_CHECKING") or (
        isinstance(node, ast.Attribute) and node.attr == "TYPE_CHECKING"
    )


def _import_nodes(tree: ast.AST, skip_type_checking: bool):
    """Yield every import node, optionally skipping `if TYPE_CHECKING:` bodies (never executed)."""
    for child in ast.iter_child_nodes(tree):
        if isinstance(child, (ast.Import, ast.ImportFrom)):
            yield child
        if skip_type_checking and isinstance(child, ast.If) and _is_type_checking_test(child.test):
            for orelse in child.orelse:  # the else branch does run
                yield from _import_nodes(ast.Module(body=[orelse], type_ignores=[]), skip_type_checking)
            continue
        yield from _import_nodes(child, skip_type_checking)


def _absolute_targets(node: ast.AST, module: str, is_package: bool) -> list[str]:
    """Resolve an import node to the absolute dotted module names it may load."""
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names]
    assert isinstance(node, ast.ImportFrom)
    if node.level == 0:
        base = node.module or ""
    else:
        package = module.split(".") if is_package else module.split(".")[:-1]
        up = node.level - 1
        if up >= len(package):
            return ["<beyond top-level package>"]
        package = package[: len(package) - up]
        base = ".".join(package + ([node.module] if node.module else []))
    # `from pkg import name` may load pkg.name as a module, so check both forms.
    return [base] + [f"{base}.{a.name}" for a in node.names if a.name != "*"]


def _imports_of(path: Path, root: Path, skip_type_checking: bool) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    module = _module_name(path, root)
    is_package = path.name == "__init__.py"
    out: list[str] = []
    for node in _import_nodes(tree, skip_type_checking):
        out.extend(_absolute_targets(node, module, is_package))
    return out


def domain_violations(root: Path = BACKEND, domain_dir: Path | None = None) -> list[str]:
    """Imports in the domain package that are neither stdlib nor inside it.

    TYPE_CHECKING blocks are *not* exempt here: the domain layer stays free of
    outside names even for typing."""
    domain_dir = domain_dir or root / "app" / "dast" / "domain"
    package = _module_name(domain_dir / "__init__.py", root)
    problems = []
    for path in sorted(domain_dir.rglob("*.py")):
        for target in _imports_of(path, root, skip_type_checking=False):
            if target == package or target.startswith(package + "."):
                continue
            if target.split(".")[0] in sys.stdlib_module_names:
                continue
            problems.append(f"{path.name}: imports {target!r}")
    return problems


def node_violations(root: Path = BACKEND, nodes_dir: Path | None = None) -> list[str]:
    """Runtime imports in `app/dast/nodes/` of routers or concrete infrastructure."""
    nodes_dir = nodes_dir or root / "app" / "dast" / "nodes"
    problems = []
    for path in sorted(nodes_dir.rglob("*.py")):
        for target in _imports_of(path, root, skip_type_checking=True):
            for prefix in NODE_FORBIDDEN_PREFIXES:
                if target == prefix or target.startswith(prefix + "."):
                    problems.append(f"{path.name}: imports {target!r}")
    return problems


def sdk_violations(root: Path = BACKEND, exempt_dirs: tuple[Path, ...] | None = None) -> list[str]:
    """Imports of a model SDK anywhere in the DAST code or the services, lazy ones included
    (only `if TYPE_CHECKING:` bodies are ignored), outside the gateway package."""
    exempt_dirs = exempt_dirs if exempt_dirs is not None else (root / "app" / "services" / "model_gateway",)
    exempt_files = {root / "app" / "services" / "agent_bridge.py"}
    problems = []
    for base in (root / "app" / "dast", root / "app" / "services"):
        for path in sorted(base.rglob("*.py")):
            if path in exempt_files or any(d in path.parents for d in exempt_dirs):
                continue
            for target in _imports_of(path, root, skip_type_checking=True):
                if any(target == p or target.startswith(p + ".") for p in MODEL_SDK_PREFIXES):
                    problems.append(f"{path.relative_to(root)}: imports {target!r}")
    return problems


# --- the real tree ---------------------------------------------------------------------------


def test_domain_package_has_the_expected_modules():
    present = {p.stem for p in DOMAIN_DIR.glob("*.py") if p.stem != "__init__"}
    assert EXPECTED_DOMAIN_MODULES <= present


def test_domain_imports_only_stdlib_and_itself():
    assert domain_violations() == []


def test_nodes_do_not_import_routers_or_concrete_infrastructure():
    assert node_violations() == []


def test_only_the_model_gateway_imports_a_model_sdk():
    assert sdk_violations() == []
    assert GATEWAY_DIR.is_dir()  # the exemption must point at something real


@pytest.mark.parametrize(
    "bad_line",
    [
        "import boto3",
        "from langchain_ollama import ChatOllama",
        "import anthropic",
        "from openai import OpenAI",
        "def f():\n    from langchain_anthropic import ChatAnthropic",  # a lazy import is still an import
        "import botocore.config",
    ],
)
def test_sdk_check_fails_on_a_stray_sdk_import(tmp_path, bad_line):
    root, domain, nodes = _fake_backend(tmp_path)
    services = root / "app" / "services"
    (services / "model_gateway").mkdir(parents=True)
    (services / "__init__.py").write_text("")
    (services / "model_gateway" / "adapters.py").write_text("import boto3\n")  # the gateway may
    (services / "fine.py").write_text("import json\nfrom typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import boto3\n")
    assert sdk_violations(root) == []
    (nodes / "stray.py").write_text(bad_line + "\n")
    assert sdk_violations(root), bad_line


def test_domain_interfaces_declare_all_contracts():
    from app.dast.domain import interfaces

    for name in (
        "RequestExecutor",
        "BrowserDriver",
        "ModelGateway",
        "CheckCatalog",
        "FindingStore",
        "CredentialHolder",
        "ModelAdapter",
    ):
        assert hasattr(interfaces, name), name


# --- the checker itself catches violations ---------------------------------------------------


def _fake_backend(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Mirror app/dast/{domain,nodes} under tmp_path so module names resolve like the real tree."""
    domain = tmp_path / "app" / "dast" / "domain"
    nodes = tmp_path / "app" / "dast" / "nodes"
    for directory in (tmp_path / "app", tmp_path / "app" / "dast", domain, nodes):
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "__init__.py").write_text("")
    return tmp_path, domain, nodes


@pytest.mark.parametrize(
    "bad_line",
    [
        "import fastapi",
        "from sqlalchemy.orm import Session",
        "import playwright.sync_api",
        "import httpx",
        "from langchain_core.messages import HumanMessage",
        "import anthropic",
        "import yaml",
        "from app.models import Finding",
        "from app import models",
        "from .. import state",
        "from ..state import GraphState",
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import fastapi",
    ],
)
def test_domain_check_fails_on_a_bad_import(tmp_path, bad_line):
    root, domain, _ = _fake_backend(tmp_path)
    (domain / "good.py").write_text("from __future__ import annotations\nimport dataclasses\nfrom . import other\nfrom .other import x\n")
    (domain / "other.py").write_text("x = 1\n")
    assert domain_violations(root) == []
    (domain / "bad.py").write_text(bad_line + "\n")
    assert domain_violations(root), bad_line


@pytest.mark.parametrize(
    "bad_line",
    [
        "from app.routers import scans",
        "from app.routers.scans import router",
        "from app.services import scan_runner",
        "from app.db import SessionLocal",
        "import playwright.sync_api",
        "from langchain_ollama import ChatOllama",
        "import boto3",
        "import httpx",
        "from httpx import Client",
        "import httpx.sync",
        "from ...routers import scans",
        "from ...services.scan_runner import execute_scan",
    ],
)
def test_nodes_check_fails_on_a_bad_import(tmp_path, bad_line):
    root, _, nodes = _fake_backend(tmp_path)
    (nodes / "ok.py").write_text("from ..state import GraphState\nfrom .. import api_analysis\nimport json\n")
    assert node_violations(root) == []
    (nodes / "bad.py").write_text(bad_line + "\n")
    assert node_violations(root), bad_line


def test_nodes_check_ignores_type_checking_only_imports(tmp_path):
    root, _, nodes = _fake_backend(tmp_path)
    (nodes / "typed.py").write_text(
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from playwright.sync_api import Page\n"
    )
    assert node_violations(root) == []


# --- domain really imports with only the standard library available --------------------------


def test_domain_modules_import_with_only_the_standard_library():
    """Import every domain module in a clean interpreter that refuses any third-party import."""
    script = textwrap.dedent(
        f"""
        import importlib, sys

        STDLIB = set(sys.stdlib_module_names)

        class BlockThirdParty:
            def find_spec(self, name, path=None, target=None):
                if name.split(".")[0] in STDLIB or name.split(".")[0] == "app":
                    return None
                raise ImportError("third-party import blocked: " + name)

        sys.meta_path.insert(0, BlockThirdParty())
        for mod in {sorted(EXPECTED_DOMAIN_MODULES)!r}:
            importlib.import_module("{DOMAIN_PACKAGE}." + mod)
        print("ok")
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=BACKEND, capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"
