"""Scan IaC and config files for hardcoded secrets."""

from __future__ import annotations

import logging
from pathlib import Path

from app.services.iac_app.scanner.secrets.entropy import extract_high_entropy_assignments
from app.services.iac_app.scanner.secrets.patterns import COMPILED_PATTERNS, PLACEHOLDER_MARKERS, RULE_META

logger = logging.getLogger(__name__)

SKIP_DIRS = {
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
    "vendor",
}

# IaC and config file extensions (secrets scanner scope)
IAC_CONFIG_EXTENSIONS = {
    # Terraform
    ".tf",
    ".tfvars",
    ".tf.json",
    # Kubernetes / Helm
    ".yaml",
    ".yml",
    # Docker
    ".dockerfile",
    # CloudFormation / Pulumi
    ".json",
    # Ansible
    ".cfg",
    ".conf",
    # General config
    ".env",
    ".ini",
    ".properties",
    ".toml",
}

# IaC and config file names (exact match, case-insensitive)
IAC_CONFIG_FILENAMES = {
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "docker-compose.json",
    ".dockerignore",
    "chart.yaml",
    "values.yaml",
    "kustomization.yaml",
    "kustomization.yml",
    "pulumi.yaml",
    "pulumi.yml",
    "serverless.yml",
    "serverless.yaml",
    "template.yaml",
    "template.yml",
    "buildspec.yml",
    "buildspec.yaml",
    "appspec.yml",
    "appspec.yaml",
    "build.gradle",
    "pom.xml",
    "package.json",
    "requirements.txt",
    "go.mod",
    "cargo.toml",
    " Gemfile",
    "config.yaml",
    "config.yml",
    "config.json",
    "settings.yaml",
    "settings.yml",
    "settings.json",
}

# Directories that contain IaC/config files
IAC_CONFIG_DIRS = {
    "terraform",
    "k8s",
    "kubernetes",
    "kustomize",
    "helm",
    "charts",
    "deploy",
    "deployment",
    "infrastructure",
    "infra",
    "iac",
    "cloudformation",
    "pulumi",
    "ansible",
    "playbooks",
    "roles",
    ".github",
    ".gitlab",
    ".circleci",
    ".travis",
}

SKIP_EXTENSIONS = {
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
    ".exe",
    ".dll",
    ".so",
    ".woff",
    ".woff2",
    ".ttf",
    ".lock",
    # Application code (not IaC)
    ".java",
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".go",
    ".rs",
    ".rb",
    ".php",
    ".c",
    ".cpp",
    ".h",
    ".cs",
    ".swift",
    ".kt",
    ".scala",
    ".r",
    ".m",
    ".mm",
    ".vue",
    ".svelte",
}

MAX_FILE_BYTES = 1_000_000


def _is_iac_config_file(path: Path) -> bool:
    """Check if a file is an IaC or config file."""
    name_lower = path.name.lower()
    suffix_lower = path.suffix.lower()

    # Check exact filename match
    if name_lower in IAC_CONFIG_FILENAMES:
        return True

    # Check extension match
    if suffix_lower in IAC_CONFIG_EXTENSIONS:
        return True

    # Check if file is in an IaC/config directory
    for part in path.parts:
        if part.lower() in IAC_CONFIG_DIRS:
            return True

    return False


class SecretScanner:
    def scan_path(self, target_path: str) -> list[dict]:
        root = Path(target_path)
        if not root.exists():
            return []
        findings: list[dict] = []
        if root.is_file():
            if _is_iac_config_file(root):
                findings.extend(self.scan_file(root, root.parent))
            return findings
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if path.suffix.lower() in SKIP_EXTENSIONS:
                continue
            if not _is_iac_config_file(path):
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            findings.extend(self.scan_file(path, root))
        return findings

    def scan_file(self, path: Path, root: Path | None = None) -> list[dict]:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []
        rel = str(path.relative_to(root)).replace("\\", "/") if root else str(path)
        findings: list[dict] = []
        seen: set[tuple[str, int, str]] = set()
        
        # Build line-to-key mapping for YAML files
        line_key_map = self._build_yaml_key_map(text) if path.suffix.lower() in ('.yaml', '.yml') else {}
        
        for line_no, line in enumerate(text.splitlines(), start=1):
            line_secret_hits = 0
            for name, pattern in COMPILED_PATTERNS.items():
                if name.startswith("GENERIC") and _is_placeholder(line):
                    continue
                for match in pattern.finditer(line):
                    snippet = match.group(0)
                    captured = match.group(match.lastindex) if match.lastindex else snippet
                    if _is_placeholder(snippet) and name.startswith("GENERIC"):
                        continue
                    if name.startswith("GENERIC") and (
                        _is_placeholder(captured) or _is_code_reference(captured)
                    ):
                        continue
                    if _is_code_reference(captured):
                        continue
                    key = (name, line_no, snippet[:24])
                    if key in seen:
                        continue
                    seen.add(key)
                    line_secret_hits += 1
                    # Get resource key from line-to-key mapping or extract from line
                    resource_key = line_key_map.get(line_no) or self._extract_resource_key(line, path)
                    findings.append(self._finding(name, rel, line_no, snippet, resource_key))
            if line_secret_hits or _is_placeholder(line):
                continue
            for key_name, value in extract_high_entropy_assignments(line):
                if _is_placeholder(value) or _is_code_reference(value):
                    continue
                key = ("HIGH_ENTROPY", line_no, value[:24])
                if key in seen:
                    continue
                seen.add(key)
                # Get resource key from line-to-key mapping or use key_name
                resource_key = line_key_map.get(line_no) or self._extract_resource_key(line, path, key_name)
                findings.append(self._finding("HIGH_ENTROPY", rel, line_no, value, resource_key))
        return findings

    def _build_yaml_key_map(self, text: str) -> dict[int, str]:
        """Build a mapping of line numbers to full YAML key paths."""
        import re
        line_key_map = {}
        stack = []  # Stack of (indent_level, key)
        
        for line_no, line in enumerate(text.splitlines(), start=1):
            # Match YAML key-value pairs
            match = re.match(r'^(\s*)([\w.-]+)\s*:', line)
            if match:
                indent = len(match.group(1))
                key = match.group(2)
                
                # Pop stack until we find the parent
                while stack and stack[-1][0] >= indent:
                    stack.pop()
                
                # Build full path
                parent_path = ".".join(k for _, k in stack)
                full_path = f"{parent_path}.{key}" if parent_path else key
                
                # Store in map
                line_key_map[line_no] = full_path
                
                # Push to stack
                stack.append((indent, key))
        
        return line_key_map

    def _extract_resource_key(self, line: str, path: Path, key_name: str | None = None) -> str:
        """Extract a resource key from line (fallback for non-YAML files)."""
        import re
        
        # Try YAML key
        yaml_match = re.match(r'^(\s*)([\w.-]+)\s*:', line)
        if yaml_match:
            return yaml_match.group(2)
        
        # Try JSON key
        json_match = re.match(r'^\s*"([^"]+)"\s*:', line)
        if json_match:
            return json_match.group(1)
        
        # Use key_name from entropy extraction if available
        if key_name:
            return key_name
        
        # Fallback to file basename
        return path.stem

    def _finding(self, rule_name: str, file_path: str, line_start: int, evidence: str, resource_key: str | None = None) -> dict:
        severity, title = RULE_META.get(rule_name, ("HIGH", "Potential secret"))
        return {
            "rule_id": f"SECRET.{rule_name}",
            "title": title,
            "description": f"{title} detected in {file_path}",
            "severity": severity,
            "category": "SECRETS",
            "finding_type": "SECRET",
            "iac_type": "common",
            "provider": None,
            "resource": resource_key or file_path,
            "resource_type": "secret",
            "scanner": "secrets",
            "detected_by": ["secrets"],
            "file_path": file_path,
            "line_start": line_start,
            "line_end": line_start,
            "evidence": _redact(evidence),
            "remediation": (
                "Remove the secret from source control, rotate the credential, "
                "and load it from a secret manager or CI variable."
            ),
            "references": [
                "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_cryptographic_key",
            ],
            "compliance": [
                {"framework": "SOC2", "control": "CC6.1"},
                {"framework": "PCI_DSS", "control": "3.5"},
                {"framework": "NIST", "control": "IA-5"},
            ],
            "cwe": "CWE-798",
            "owasp_category": "A07:2021",
        }


def _is_placeholder(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)


_CODE_REF_PREFIXES = (
    "var.",
    "local.",
    "data.",
    "module.",
    "path.",
    "count.",
    "each.",
    "self.",
    "terraform.",
)


def _is_code_reference(text: str) -> bool:
    """Skip Terraform/HCL references that are not literal secrets."""
    stripped = (text or "").strip().strip("'\"")
    lowered = stripped.lower()
    if any(lowered.startswith(prefix) for prefix in _CODE_REF_PREFIXES):
        return True
    if stripped.startswith("${") or "${" in stripped:
        return True
    return False


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "********"
    return f"{value[:4]}********"
