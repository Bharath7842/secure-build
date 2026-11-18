"""Terraform collector — static parsing of lockfiles and ``.tf`` manifests.

Static only: no ``terraform init/providers``, no registry network access.

Evidence model (§5/§13):

- ``.terraform.lock.hcl`` pins exact provider versions *and* package hashes
  (``zh:`` zip SHA-256, ``h1:`` content SHA-256); entries that cannot be
  decoded are dropped, never invented.
- A provider declared in a **root-level** ``required_providers`` block is a
  direct dependency of the project; anything only the lockfile or a nested
  module knows about is transitive.
"""

import re
from pathlib import Path

from .base import DependencyCollector, rel_posix, sri_hashes


# provider "registry.terraform.io/hashicorp/aws" { version = "5.31.0" ... }
_LOCK_PROVIDER = re.compile(
    r"""provider\s+["'](?P<source>[^"']+)["']\s*\{(?P<body>[^}]*)\}""",
    re.S,
)
_LOCK_VERSION = re.compile(r"""version\s*=\s*["'](?P<version>[^"']+)["']""")

# source  = "hashicorp/aws"   /   version = "~> 5.0"
_SOURCE_LINE = re.compile(r"""source\s*=\s*["'](?P<source>[^"']+)["']""")
_VERSION_LINE = re.compile(r"""version\s*=\s*["'](?P<version>[^"']+)["']""")

# required_providers { name = { source = ..., version = ... } } — the block
# is brace-balanced rather than regex-terminated: standard `terraform fmt`
# indents each entry's closing brace, which a lazy `.*?\}` cannot cross.
_REQUIRED_HEAD = re.compile(r"""\brequired_providers\s*\{""")
_PROVIDER_BLOCK = re.compile(
    r"""(?P<name>[A-Za-z0-9_-]+)\s*=\s*\{(?P<body>[^{}]*)\}""",
    re.S,
)

# hashes = ["h1:<base64>", "zh:<hex>", "sha256:<hex>"]
_HASHES_LIST = re.compile(r"""hashes\s*=\s*\[(?P<body>[^\]]*)\]""", re.S)
_HASH_ENTRY = re.compile(r"""["'](?P<kind>zh|h1|sha256):(?P<value>[^\s"']+)["']""")
_ZH_HEX = re.compile(r"""[0-9a-fA-F]{64}""")

# module "vpc" { source = "..." version = "..." }
_MODULE_BLOCK = re.compile(
    r"""module\s+["'](?P<name>[^"']+)["']\s*\{(?P<body>[^}]*)\}""",
    re.S,
)


def _split_source(source: str) -> tuple[str, str]:
    """`hashicorp/aws` or `registry.terraform.io/hashicorp/aws` -> (namespace, name)."""
    parts = [p for p in source.split("/") if p]
    if parts and parts[0] in ("registry.terraform.io", "app.terraform.io"):
        parts = parts[1:]
    if len(parts) >= 2:
        return "/".join(parts[:-1]), parts[-1]
    return "", source


def _brace_blocks(content: str) -> list[str]:
    """Bodies of every ``required_providers { ... }`` block, brace-balanced."""
    bodies: list[str] = []
    for match in _REQUIRED_HEAD.finditer(content):
        depth = 1
        index = match.end()
        in_string = False
        while index < len(content) and depth:
            char = content[index]
            if in_string:
                if char == "\\":
                    index += 1
                elif char == '"':
                    in_string = False
            elif char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            index += 1
        if depth == 0:
            bodies.append(content[match.end():index - 1])
    return bodies


def _declared_providers(content: str) -> set[tuple[str, str]]:
    """``(namespace, name)`` identities declared in ``required_providers``."""
    declared: set[tuple[str, str]] = set()
    for body in _brace_blocks(content):
        for block in _PROVIDER_BLOCK.finditer(body):
            name = block.group("name")
            source_match = _SOURCE_LINE.search(block.group("body"))
            if source_match:
                declared.add(_split_source(source_match.group("source")))
            else:
                # A source-less entry defaults to the hashicorp namespace (§4).
                declared.add(("hashicorp", name))
    return declared


def _extract_hashes(body: str) -> list[dict]:
    """Lockfile ``hashes`` entries as CycloneDX hashes; undecodable dropped."""
    block = _HASHES_LIST.search(body)
    if not block:
        return []
    hashes: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for match in _HASH_ENTRY.finditer(block.group("body")):
        kind = match.group("kind")
        value = match.group("value")
        if kind == "zh":
            if not _ZH_HEX.fullmatch(value):
                continue
            found = [{"alg": "SHA-256", "content": value.lower()}]
        else:
            # `h1:` (base64 of the unpacked package) and legacy `sha256:`
            # entries are both SHA-256 digests.
            found = sri_hashes(f"sha256-{value}")
        for entry in found:
            key = (entry["alg"], entry["content"])
            if key in seen:
                continue
            seen.add(key)
            hashes.append(entry)
    return hashes


class TerraformCollector(DependencyCollector):

    def supported_files(self) -> list[str]:
        return [".terraform.lock.hcl", "*.tf"]

    def collect(self, project_path: Path) -> list[dict]:
        components: list[dict] = []
        pins: set[str] = set()        # identity@version pinned by a lockfile
        pinned: set[str] = set()      # identities the lockfile already covers
        seen: set[str] = set()        # manifest identities already collected

        tf_files: list[tuple[Path, str]] = []
        for tf_file in sorted(project_path.rglob("*.tf")):
            try:
                tf_files.append((tf_file, tf_file.read_text(encoding="utf-8-sig")))
            except OSError:
                continue

        # Only root-level manifests declare what the project itself requires.
        root_declared: set[tuple[str, str]] = set()
        for tf_file, content in tf_files:
            if "/" not in rel_posix(tf_file, project_path):
                root_declared |= _declared_providers(content)

        # Lockfile pins exact versions (§5.3) — collect it first.
        for lock in sorted(project_path.rglob(".terraform.lock.hcl")):
            for comp in self._parse_lockfile(lock, project_path, root_declared):
                key = comp.pop("_dedupe_key", "")
                if key in pins:
                    continue
                pins.add(key)
                pinned.add(key.rsplit("@", 1)[0])
                components.append(comp)

        # A manifest constraint never duplicates a lockfile pin of its provider.
        for tf_file, content in tf_files:
            for comp in self._parse_tf(tf_file, content, project_path):
                key = comp.pop("_dedupe_key", "")
                if not key or key in seen or key in pinned:
                    continue
                seen.add(key)
                components.append(comp)

        return components

    def _parse_lockfile(self, lock_path: Path, root_path: Path,
                        root_declared: set[tuple[str, str]]) -> list[dict]:
        try:
            content = lock_path.read_text(encoding="utf-8-sig")
        except OSError:
            return []

        rel = rel_posix(lock_path, root_path)
        results = []
        for match in _LOCK_PROVIDER.finditer(content):
            source = match.group("source")
            body = match.group("body")
            version_match = _LOCK_VERSION.search(body)
            if not version_match:
                continue
            namespace, name = _split_source(source)
            results.append(self._component(
                name=name, namespace=namespace, version=version_match.group("version"),
                source_file=rel, registry_url=source,
                direct=(namespace, name) in root_declared,
                hashes=_extract_hashes(body),
                dedupe=f"{namespace}/{name}@{version_match.group('version')}",
            ))
        return results

    def _parse_tf(self, tf_path: Path, content: str, root_path: Path) -> list[dict]:
        rel = rel_posix(tf_path, root_path)
        # Evidence: only a root-level manifest declares a *project* dependency.
        direct = "/" not in rel
        results: list[dict] = []
        seen: set[str] = set()

        for body in _brace_blocks(content):
            for block in _PROVIDER_BLOCK.finditer(body):
                local_name = block.group("name")
                entry = block.group("body")
                source_match = _SOURCE_LINE.search(entry)
                source = source_match.group("source") if source_match else ""
                if source:
                    namespace, name = _split_source(source)
                else:
                    # Source omitted: terraform defaults to the hashicorp namespace.
                    namespace, name = "hashicorp", local_name
                key = f"{namespace}/{name}"
                if key in seen:
                    continue
                seen.add(key)
                version_match = _VERSION_LINE.search(entry)
                results.append(self._component(
                    name=name, namespace=namespace,
                    version=version_match.group("version") if version_match else "",
                    source_file=rel,
                    registry_url=source or f"hashicorp/{name}",
                    direct=direct,
                    dedupe=key,
                ))

        for module in _MODULE_BLOCK.finditer(content):
            body = module.group("body")
            source_match = _SOURCE_LINE.search(body)
            if not source_match:
                continue
            version_match = _VERSION_LINE.search(body)
            source = source_match.group("source")
            # Module registry sources are `<NAMESPACE>/<NAME>/<PROVIDER>`.
            parts = [p for p in source.split("/") if p]
            if len(parts) >= 3:
                namespace, name = parts[0], parts[1]
            else:
                namespace, name = _split_source(source)
            key = f"module:{source}"
            if key in seen:
                continue
            seen.add(key)
            results.append(self._component(
                name=name, namespace=namespace,
                version=version_match.group("version") if version_match else "",
                source_file=rel, registry_url=source, direct=direct,
                dedupe=key,
            ))

        return results

    @staticmethod
    def _component(*, name: str, namespace: str, version: str, source_file: str,
                   registry_url: str, direct: bool, dedupe: str,
                   hashes: list[dict] | None = None) -> dict:
        return {
            "name": name,
            "group": namespace,
            "version": version,
            "ecosystem": "terraform",
            "scope": "runtime",
            "direct": direct,
            "source_file": source_file,
            "hashes": hashes or [],
            "depends_on": [],
            "registry_url": f"https://registry.terraform.io/{registry_url}",
            "_dedupe_key": dedupe,
        }
