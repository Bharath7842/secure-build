"""Deno collector — static parsing of ``deno.lock`` and ``deno.json``/``deno.jsonc``.

Static only: no ``deno info`` invocation, no network access. ``remote``
(https-import) entries are source files rather than packages, so they are not
recorded as components.
"""

import json
import re
from pathlib import Path
from urllib.parse import quote

from .base import (
    DependencyCollector,
    jsonc_loads,
    path_ignored,
    purl_for,
    rel_posix,
    sri_hashes,
)


def _split_name_version(key: str) -> tuple[str, str]:
    """``@scope/name@1.2.3_peer@9`` -> (``@scope/name``, ``1.2.3``).

    Returns ``(key, "")`` when there is no digit-leading exact version after
    the name (bare names, ``^``/``~`` ranges and unprefixed specifiers).
    """
    at = key.find("@", 1) if key.startswith("@") else key.find("@")
    if at <= 0:
        return key, ""
    name, rest = key[:at], key[at + 1:]
    version = rest.split("_", 1)[0]
    if not version or not version[0].isdigit():
        return name, ""
    return name, version


def _full_name(comp: dict) -> str:
    """Scoped identity (``@scope/name``) from a component's group/name pair."""
    group = comp.get("group", "")
    name = comp.get("name", "")
    return f"{group}/{name}" if group else str(name)


class DenoCollector(DependencyCollector):

    def supported_files(self) -> list[str]:
        return ["deno.lock", "deno.json", "deno.jsonc"]

    def collect(self, project_path: Path) -> tuple[list[dict], list[dict]]:
        direct_names: set[str] = set()
        manifest_comps: list[dict] = []
        root_name, root_version = "", ""

        manifests = sorted(
            set(project_path.rglob("deno.json")) | set(project_path.rglob("deno.jsonc"))
        )
        for manifest in manifests:
            if path_ignored(manifest.relative_to(project_path)):
                continue
            data = self._read_manifest(manifest)
            if not data:
                continue
            if manifest.parent == project_path and not root_name:
                name = data.get("name")
                version = data.get("version")
                root_name = name if isinstance(name, str) else ""
                root_version = version if isinstance(version, str) else ""
            for comp in self._parse_manifest(manifest, data, project_path):
                full = _full_name(comp)
                if full not in direct_names:
                    direct_names.add(full)
                manifest_comps.append(comp)

        components: list[dict] = []
        for lock in sorted(project_path.rglob("deno.lock")):
            if path_ignored(lock.relative_to(project_path)):
                continue
            components.extend(self._parse_lock(lock, project_path, direct_names))

        if components:
            known = {_full_name(c) for c in components}
            components.extend(c for c in manifest_comps if _full_name(c) not in known)
        else:
            components = manifest_comps

        edges: list[dict] = []
        direct_purls = sorted({c["purl"] for c in components if c.get("direct")})
        if root_name and direct_purls:
            root = f"pkg:generic/{quote(root_name, safe='')}"
            if root_version:
                root += f"@{root_version}"
            edges.append({"ref": root, "dependsOn": direct_purls})
        return components, edges

    @staticmethod
    def _read_manifest(path: Path) -> dict:
        try:
            text = path.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError):
            return {}
        try:
            data = jsonc_loads(text)
        except ValueError:
            return {}
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _import_targets(data: dict) -> list[str]:
        imports = data.get("imports")
        if not isinstance(imports, dict):
            return []
        return [t for t in imports.values() if isinstance(t, str)]

    def _parse_manifest(self, path: Path, data: dict, root_path: Path) -> list[dict]:
        source = rel_posix(path, root_path)
        results: list[dict] = []
        for target in self._import_targets(data):
            if target.startswith("jsr:"):
                kind = "jsr"
                body = target[4:]
            elif target.startswith("npm:"):
                kind = "npm"
                body = target[4:]
            else:
                # https:/relative/file imports are source files, not packages.
                continue
            at = body.find("@", 1) if body.startswith("@") else body.find("@")
            if at > 0:
                name, version = body[:at], body[at + 1:]
            else:
                name, version = body, ""
            comp = self._build_component(name, version, kind, source)
            if comp:
                comp["direct"] = True
                results.append(comp)
        return results

    def _parse_lock(
        self, lock: Path, root_path: Path, direct_names: set[str]
    ) -> list[dict]:
        try:
            data = json.loads(lock.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return []
        if not isinstance(data, dict):
            return []
        npm_map = data.get("npm")
        jsr_map = data.get("jsr")
        npm_map = npm_map if isinstance(npm_map, dict) else {}
        jsr_map = jsr_map if isinstance(jsr_map, dict) else {}
        if not npm_map and not jsr_map:
            # Older lock versions (v1-v3) carry no package maps we can parse;
            # fall through to the manifest evidence (§5.3).
            return []
        specifiers = data.get("specifiers")
        specifiers = specifiers if isinstance(specifiers, dict) else {}
        source = rel_posix(lock, root_path)

        components: list[dict] = []
        seen: set[tuple[str, str]] = set()

        for key, val in npm_map.items():
            if not isinstance(key, str):
                continue
            name, version = _split_name_version(key)
            if not name or not version or (name, version) in seen:
                continue
            seen.add((name, version))
            info = val if isinstance(val, dict) else {}
            integrity = info.get("integrity") if isinstance(info.get("integrity"), str) else ""
            comp = self._build_component(name, version, "npm", source)
            if not comp:
                continue
            comp["hashes"] = sri_hashes(integrity)
            comp["_dep_specs"] = self._dep_specs(info.get("dependencies"))
            components.append(comp)

        for key, val in jsr_map.items():
            if not isinstance(key, str):
                continue
            name, version = _split_name_version(key)
            if not name or not version or (name, version) in seen:
                continue
            seen.add((name, version))
            info = val if isinstance(val, dict) else {}
            integrity = str(info.get("integrity") or "")
            comp = self._build_component(name, version, "jsr", source)
            if not comp:
                continue
            if re.fullmatch(r"[0-9a-f]{64}", integrity, re.IGNORECASE):
                comp["hashes"] = [{"alg": "SHA-256", "content": integrity.lower()}]
            else:
                comp["hashes"] = sri_hashes(integrity)
            comp["_dep_specs"] = self._dep_specs(info.get("dependencies"))
            components.append(comp)

        if not components:
            return []

        exact: dict[tuple[str, str], str] = {}
        versions: dict[str, set[str]] = {}
        for comp in components:
            full = _full_name(comp)
            exact[(full, comp["version"])] = comp["purl"]
            versions.setdefault(full, set()).add(comp["version"])

        def resolve(spec: str) -> str | None:
            body = spec.removeprefix("jsr:").removeprefix("npm:")
            if spec in specifiers and isinstance(specifiers[spec], str):
                sname = _split_name_version(body)[0]
                purl = exact.get((sname, specifiers[spec]))
                if purl:
                    return purl
            name, version = _split_name_version(body)
            if version:
                return exact.get((name, version))
            found = versions.get(name) or set()
            return exact.get((name, next(iter(found)))) if len(found) == 1 else None

        for comp in components:
            resolved: list[str] = []
            for spec in comp.pop("_dep_specs", []):
                purl = resolve(spec)
                if purl and purl != comp["purl"] and purl not in resolved:
                    resolved.append(purl)
            comp["depends_on"] = resolved
            comp["direct"] = _full_name(comp) in direct_names
        return components

    @staticmethod
    def _dep_specs(value) -> list[str]:
        if isinstance(value, list):
            return [v for v in value if isinstance(v, str)]
        if isinstance(value, dict):
            return [v for v in value.values() if isinstance(v, str)]
        return []

    @staticmethod
    def _build_component(name: str, version: str, kind: str, source: str) -> dict | None:
        if not name or not version:
            return None
        if kind == "npm":
            group, short = (name.split("/", 1) if name.startswith("@") and "/" in name
                            else ("", name))
            comp = {
                "name": short,
                "group": group,
                "version": version,
                "ecosystem": "deno",
                "scope": "compile",
                "direct": False,
                "source_file": source,
                "hashes": [],
                "registry_url": f"https://www.npmjs.com/package/{name}",
            }
        else:
            group, short = (name.split("/", 1) if name.startswith("@") and "/" in name
                            else ("", name))
            comp = {
                "name": short,
                "group": group,
                "version": version,
                "ecosystem": "deno",
                "purl_type": "generic",
                "purl_qualifier": "jsr",
                "scope": "compile",
                "direct": False,
                "source_file": source,
                "hashes": [],
                "registry_url": f"https://jsr.io/{name}",
            }
        comp["depends_on"] = []
        comp["purl"] = purl_for(comp)
        return comp
