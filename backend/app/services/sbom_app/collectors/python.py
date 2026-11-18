import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import httpx
import tomllib

from .base import DependencyCollector, rel_posix

# Ordered best-first: the first source present in a project dir wins (§5.3).
_LOCKFILES = ("uv.lock", "pdm.lock", "poetry.lock", "Pipfile.lock", "requirements.txt")
_MANIFESTS = ("pyproject.toml", "Pipfile", "setup.py", "setup.cfg")


def _requirement_name(req: str) -> str:
    """Package name from a PEP 508 requirement (``pkg[extra]>=1; marker``)."""
    return re.split(r"[\[<>=!~;@\s]", req.strip())[0]


class PythonCollector(DependencyCollector):

    def supported_files(self) -> list[str]:
        return [
            "requirements.txt",
            "pyproject.toml",
            "Pipfile",
            "setup.py",
            "setup.cfg",
            "poetry.lock",
            "uv.lock",
            "pdm.lock",
        ]

    def collect(self, project_path: Path) -> tuple[list[dict], list[dict]]:
        """Lockfile/manifest per project directory — never the scanner's own env.

        ``pip list`` reports the interpreter running the scan, so it is only
        consulted when a project-local virtualenv exists *and* no manifest
        or lockfile could be parsed.
        """
        components: list[dict] = []
        edges: list[dict] = []

        for manifest_dir in self._project_dirs(project_path):
            comps, dir_edges = self._collect_dir(manifest_dir, project_path)
            components.extend(comps)
            edges.extend(dir_edges)

        if not components and self._command_exists("pip"):
            venv_python = self._find_project_venv(project_path)
            if venv_python:
                components.extend(self._run_pip_list(project_path, venv_python))

        return components, edges

    def _project_dirs(self, project_path: Path) -> list[Path]:
        dirs: set[Path] = set()
        for pattern in ("uv.lock", "pdm.lock", "poetry.lock", "Pipfile.lock",
                        "requirements*.txt", "pyproject.toml", "Pipfile",
                        "setup.py", "setup.cfg"):
            for match in project_path.rglob(pattern):
                if "node_modules" in match.parts or ".venv" in match.parts:
                    continue
                dirs.add(match.parent)
        return sorted(dirs)

    def _collect_dir(self, manifest_dir: Path, root_path: Path) -> tuple[list[dict], list[dict]]:
        for lock_name, parser in (
            ("uv.lock", self._parse_uv_lock),
            ("pdm.lock", self._parse_pdm_lock),
            ("poetry.lock", self._parse_poetry_lock),
            ("Pipfile.lock", self._parse_pipfile_lock),
            ("requirements.txt", self._parse_requirements_tree),
        ):
            lockfile = manifest_dir / lock_name
            if lockfile.exists():
                comps, edges = parser(lockfile, root_path, manifest_dir)
                if comps:
                    return comps, edges

        components: list[dict] = []
        for name, parser in (
            ("pyproject.toml", self._parse_pyproject),
            ("Pipfile", self._parse_pipfile),
            ("setup.py", self._parse_setup_py),
            ("setup.cfg", self._parse_setup_cfg),
        ):
            path = manifest_dir / name
            if path.exists():
                components.extend(parser(path, root_path))

        # requirements*.txt variants alongside (or instead of) requirements.txt
        for req in sorted(manifest_dir.glob("requirements*.txt")):
            components.extend(self._parse_requirements(req, root_path))

        return components, []

    @staticmethod
    def _find_project_venv(project_path: Path) -> Path | None:
        for cfg in project_path.rglob("pyvenv.cfg"):
            venv = cfg.parent
            for candidate in (venv / "Scripts" / "python.exe", venv / "bin" / "python"):
                if candidate.exists():
                    return candidate
        return None

    def _run_pip_list(self, project_path: Path, python_exe: Path | None = None) -> list[dict]:
        cmd = [str(python_exe), "-m", "pip", "list", "--format=json"] if python_exe else [
            "pip", "list", "--format=json",
        ]
        output = self._run_cli(cmd, cwd=project_path, timeout=60)
        if not output:
            return []

        import json
        packages = json.loads(output)
        results: list[dict] = []
        seen: set[str] = set()
        pending: list[tuple[int, str, str]] = []

        for idx, pkg in enumerate(packages):
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            if not name or not version:
                continue
            if name in seen:
                continue
            seen.add(name)
            pending.append((idx, name, version))

        hash_results: dict[int, list[dict]] = {}
        with httpx.Client(timeout=5.0, limits=httpx.Limits(max_connections=10)) as client:
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {
                    executor.submit(self._fetch_pypi_hash_with_client, client, name, version): idx
                    for idx, name, version in pending
                }
                for future in as_completed(futures):
                    idx = futures[future]
                    try:
                        hash_results[idx] = future.result()
                    except Exception:
                        hash_results[idx] = []

        for idx, name, version in pending:
            results.append({
                "name": name.lower(),
                "group": "",
                "version": version,
                "ecosystem": "pypi",
                "scope": "compile",
                "optional": False,
                # pip list runs only when no static evidence exists (§5.3),
                # so every listed package is project-level direct evidence.
                "direct": True,
                "source_file": "pip list",
                "registry_url": f"https://pypi.org/project/{name}/",
                "hashes": hash_results.get(idx, []),
                "depends_on": [],
            })

        return results

    def _fetch_pypi_hash_with_client(self, client: httpx.Client, name: str, version: str) -> list[dict]:
        hashes = []
        try:
            url = f"https://pypi.org/pypi/{name}/{version}/json"
            resp = client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                for digests in data.get("urls", []):
                    sha256 = digests.get("digests", {}).get("sha256")
                    if sha256:
                        hashes.append({"alg": "SHA-256", "content": sha256})
                        break
        except Exception:
            pass
        return hashes

    def _parse_poetry_lock(
        self, lock_path: Path, root_path: Path, manifest_dir: Path | None = None
    ) -> tuple[list[dict], list[dict]]:
        results: list[dict] = []
        edges: list[dict] = []
        try:
            content = lock_path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            return results, edges

        source = rel_posix(lock_path, root_path)
        direct_names = self._declared_names(manifest_dir or lock_path.parent)
        packages: dict[str, str] = {}
        blocks: list[dict] = []

        current: dict | None = None
        in_deps = False
        for raw in content.splitlines():
            stripped = raw.strip()
            if stripped == "[[package]]":
                if current:
                    blocks.append(current)
                current = {"dependencies": {}}
                in_deps = False
                continue
            if current is None:
                continue
            if stripped.startswith("["):
                in_deps = stripped in ("[package.dependencies]", "[package.dev-dependencies]")
                continue
            if in_deps and "=" in stripped and not stripped.startswith("#"):
                dep_name, _, dep_req = stripped.partition("=")
                current["dependencies"][dep_name.strip().strip('"')] = dep_req.strip()
                continue
            match = re.match(r'(name|version|optional)\s*=\s*"?(.+?)"?$', stripped)
            if match:
                current[match.group(1)] = match.group(2).strip()
        if current:
            blocks.append(current)

        for block in blocks:
            name = block.get("name", "")
            version = block.get("version", "")
            if not name or not version:
                continue
            packages[name.lower()] = version

        for block in blocks:
            name = block.get("name", "")
            version = block.get("version", "")
            if not name or not version:
                continue
            purl = f"pkg:pypi/{name.lower()}@{version}"
            depends_on = [
                f"pkg:pypi/{dep.lower()}@{packages[dep.lower()]}"
                for dep in block.get("dependencies", {})
                if dep.lower() in packages
            ]
            results.append({
                "name": name.lower(),
                "group": "",
                "version": version,
                "ecosystem": "pypi",
                "scope": "compile",
                "optional": block.get("optional", "false") == "true",
                "direct": name.lower() in direct_names,
                "source_file": source,
                "registry_url": f"https://pypi.org/project/{name}/",
                "depends_on": depends_on,
            })
            if depends_on:
                edges.append({"ref": purl, "dependsOn": depends_on})

        return results, edges

    @staticmethod
    def _requirement_names(section) -> set[str]:
        """Package names from requirement strings or ``{name: ...}`` tables (§13)."""
        names: set[str] = set()

        def walk(obj) -> None:
            if isinstance(obj, str):
                name = _requirement_name(obj)
                if name:
                    names.add(name.lower())
            elif isinstance(obj, list):
                for item in obj:
                    walk(item)
            elif isinstance(obj, dict):
                found = obj.get("name")
                if isinstance(found, str) and found:
                    names.add(found.lower())
                else:
                    for key, value in obj.items():
                        if key != "name":
                            walk(value)

        walk(section)
        return names

    @staticmethod
    def _resolve_python_dep_purls(components: list[dict]) -> None:
        """Link stored ``_dep_names`` to exact purls by name (§13).

        A name with zero or several candidate versions cannot be resolved
        honestly from the lockfile alone, so it links nothing — matching
        ``canonicalize_relationships`` dropping ambiguous versionless refs.
        """
        index: dict[str, list[str]] = {}
        for comp in components:
            index.setdefault(comp["name"], []).append(
                f"pkg:pypi/{comp['name']}@{comp['version']}"
            )
        for comp in components:
            self_purl = f"pkg:pypi/{comp['name']}@{comp['version']}"
            depends_on: list[str] = []
            for dep_name in comp.pop("_dep_names", None) or []:
                candidates = index.get(dep_name) or []
                if (
                    len(candidates) == 1
                    and candidates[0] != self_purl
                    and candidates[0] not in depends_on
                ):
                    depends_on.append(candidates[0])
            comp["depends_on"] = depends_on

    @staticmethod
    def _python_edges(components: list[dict]) -> list[dict]:
        edges = [
            {"ref": f"pkg:pypi/{c['name']}@{c['version']}", "dependsOn": c["depends_on"]}
            for c in components if c.get("depends_on")
        ]
        return edges

    def _parse_uv_lock(
        self, lock_path: Path, root_path: Path, manifest_dir: Path | None = None
    ) -> tuple[list[dict], list[dict]]:
        """uv.lock: resolved dependency graph, artifact hashes, root direct evidence."""
        try:
            data = tomllib.loads(lock_path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
            return [], []
        source = rel_posix(lock_path, root_path)

        runtime_direct: set[str] = set()
        dev_direct: set[str] = set()
        root_name = ""
        root_version = ""
        entries: list[dict] = []

        for pkg in data.get("package") or []:
            if not isinstance(pkg, dict):
                continue
            src = pkg.get("source") if isinstance(pkg.get("source"), dict) else {}
            if set(src) & {"virtual", "editable", "workspace"}:
                # The project itself or a workspace member (§4: project code,
                # not a third-party component) — its dependencies are direct.
                if src.get("virtual") in (".", "") or src.get("editable") in (".", ""):
                    root_name = root_name or str(pkg.get("name", ""))
                    root_version = root_version or str(pkg.get("version", ""))
                runtime_direct |= self._requirement_names(pkg.get("dependencies"))
                meta = pkg.get("metadata") if isinstance(pkg.get("metadata"), dict) else {}
                runtime_direct |= self._requirement_names(meta.get("requires-dist"))
                dev_direct |= self._requirement_names(meta.get("requires-dev"))
                continue
            entries.append(pkg)

        if not runtime_direct and not dev_direct:
            runtime_direct = self._declared_names(manifest_dir or lock_path.parent)

        components: list[dict] = []
        for pkg in entries:
            name = str(pkg.get("name", ""))
            version = str(pkg.get("version", ""))
            if not name or not version:
                continue
            key = name.lower()
            src = pkg.get("source") if isinstance(pkg.get("source"), dict) else {}
            registry = src.get("registry") if isinstance(src.get("registry"), str) else ""
            if registry:
                registry_url = (
                    f"https://pypi.org/project/{name}/"
                    if "pypi.org" in registry else registry
                )
            else:
                registry_url = ""

            hashes: list[dict] = []
            sdist = pkg.get("sdist")
            wheels = pkg.get("wheels") if isinstance(pkg.get("wheels"), list) else []
            for artifact in [sdist, *wheels]:
                if not isinstance(artifact, dict):
                    continue
                digest = artifact.get("hash")
                if isinstance(digest, str) and digest.startswith("sha256:"):
                    hashes = [{"alg": "SHA-256", "content": digest.split(":", 1)[1]}]
                    break

            dep_names: list[str] = []
            for dep in pkg.get("dependencies") or []:
                dep_name = dep.get("name") if isinstance(dep, dict) else dep
                if isinstance(dep_name, str) and dep_name:
                    dep_names.append(dep_name.lower())

            components.append({
                "name": key,
                "group": "",
                "version": version,
                "ecosystem": "pypi",
                "scope": "dev" if key in dev_direct and key not in runtime_direct else "compile",
                "optional": False,
                "direct": key in (runtime_direct | dev_direct),
                "source_file": source,
                "registry_url": registry_url,
                "hashes": hashes,
                "_dep_names": dep_names,
            })

        self._resolve_python_dep_purls(components)
        edges = self._python_edges(components)
        if root_name:
            root_purl = (
                f"pkg:pypi/{root_name.lower()}@{root_version}" if root_version
                else f"pkg:pypi/{root_name.lower()}"
            )
            direct_purls = sorted({
                f"pkg:pypi/{c['name']}@{c['version']}"
                for c in components if c["direct"]
            })
            if direct_purls:
                edges.append({"ref": root_purl, "dependsOn": direct_purls})
        return components, edges

    def _parse_pdm_lock(
        self, lock_path: Path, root_path: Path, manifest_dir: Path | None = None
    ) -> tuple[list[dict], list[dict]]:
        """pdm.lock: packages with groups/dep specs and per-file sha256 hashes."""
        try:
            data = tomllib.loads(lock_path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
            return [], []
        source = rel_posix(lock_path, root_path)
        direct = self._declared_names(manifest_dir or lock_path.parent)

        results: list[dict] = []
        for pkg in data.get("package") or []:
            if not isinstance(pkg, dict):
                continue
            name = str(pkg.get("name", ""))
            version = str(pkg.get("version", ""))
            if not name or not version:
                continue
            key = name.lower()

            groups = pkg.get("groups") if isinstance(pkg.get("groups"), list) else []
            scope = "compile" if (not groups or "default" in groups) else "dev"

            hashes: list[dict] = []
            for entry in pkg.get("files") or []:
                if not isinstance(entry, dict):
                    continue
                digest = entry.get("hash")
                if isinstance(digest, str) and digest.startswith("sha256:"):
                    hashes = [{"alg": "SHA-256", "content": digest.split(":", 1)[1]}]
                    break

            dep_names: list[str] = []
            for req in pkg.get("dependencies") or []:
                if isinstance(req, str):
                    dep_name = _requirement_name(req)
                    if dep_name:
                        dep_names.append(dep_name.lower())

            results.append({
                "name": key,
                "group": "",
                "version": version,
                "ecosystem": "pypi",
                "scope": scope,
                "optional": False,
                "direct": key in direct,
                "source_file": source,
                "registry_url": f"https://pypi.org/project/{name}/",
                "hashes": hashes,
                "_dep_names": dep_names,
            })

        self._resolve_python_dep_purls(results)
        edges = self._python_edges(results)
        direct_purls = sorted({
            f"pkg:pypi/{c['name']}@{c['version']}"
            for c in results if c["direct"]
        })
        if direct_purls:
            root = self._project_identity(manifest_dir or lock_path.parent)
            if root[0]:
                root_purl = f"pkg:pypi/{root[0].lower()}@{root[1]}" if root[1] else f"pkg:pypi/{root[0].lower()}"
                edges.append({"ref": root_purl, "dependsOn": direct_purls})
        return results, edges

    @staticmethod
    def _project_identity(manifest_dir: Path) -> tuple[str, str]:
        """Project name/version from ``pyproject.toml`` — empty when absent (§4)."""
        pyproject = manifest_dir / "pyproject.toml"
        if not pyproject.exists():
            return "", ""
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
            return "", ""
        project = data.get("project") or {}
        name = project.get("name", "")
        version = project.get("version", "")
        return (
            name if isinstance(name, str) else "",
            version if isinstance(version, str) else "",
        )

    @staticmethod
    def _declared_names(manifest_dir: Path) -> set[str]:
        """Names the project itself declares — those are the direct dependencies."""
        names: set[str] = set()
        pyproject = manifest_dir / "pyproject.toml"
        if pyproject.exists():
            try:
                data = tomllib.loads(pyproject.read_text(encoding="utf-8-sig"))
            except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
                data = {}

            def collect(section) -> None:
                if isinstance(section, str):
                    name = _requirement_name(section)
                    if name:
                        names.add(name)
                elif isinstance(section, list):
                    for item in section:
                        collect(item)
                elif isinstance(section, dict):
                    for key, value in section.items():
                        if isinstance(value, (list, dict)):
                            # Group container (optional-dependencies, PEP 735
                            # dependency-groups, pdm dev-dependencies, poetry
                            # groups): the key is a group name, not a package.
                            collect(value)
                        elif isinstance(key, str) and key and not key.startswith("_"):
                            # name → spec mapping (poetry-style dependencies).
                            names.add(key)

            tool = data.get("tool") or {}
            collect(data.get("project", {}).get("dependencies", []))
            collect(data.get("project", {}).get("optional-dependencies"))
            collect(data.get("dependency-groups"))
            collect((tool.get("poetry") or {}).get("dependencies"))
            collect((tool.get("poetry") or {}).get("group"))
            collect((tool.get("pdm") or {}).get("dev-dependencies"))
        req = manifest_dir / "requirements.txt"
        if req.exists():
            try:
                for line in req.read_text(encoding="utf-8-sig").splitlines():
                    line = line.strip()
                    if line and not line.startswith(("#", "-")):
                        names.add(re.split(r"[=><!~;\s\[]", line)[0])
            except UnicodeDecodeError:
                pass
        return {n.lower() for n in names if n}

    def _parse_requirements_tree(
        self, req_path: Path, root_path: Path, manifest_dir: Path | None = None
    ) -> tuple[list[dict], list[dict]]:
        """All requirements*.txt in the directory, treated as direct dependencies."""
        components: list[dict] = []
        target_dir = manifest_dir or req_path.parent
        for req in sorted(target_dir.glob("requirements*.txt")):
            components.extend(self._parse_requirements(req, root_path))
        return components, []

    def _parse_pipfile_lock(
        self, lock_path: Path, root_path: Path, manifest_dir: Path | None = None
    ) -> tuple[list[dict], list[dict]]:
        import json

        try:
            data = json.loads(lock_path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return [], []

        source = rel_posix(lock_path, root_path)
        direct = self._declared_names(manifest_dir or lock_path.parent)
        results = []
        for section, scope in (("default", "compile"), ("develop", "dev")):
            for name, meta in (data.get(section) or {}).items():
                version = (meta or {}).get("version", "").lstrip("=") or ""
                results.append({
                    "name": name.lower(),
                    "group": "",
                    "version": version,
                    "ecosystem": "pypi",
                    "scope": scope,
                    "optional": False,
                    "direct": name.lower() in direct,
                    "source_file": source,
                    "registry_url": f"https://pypi.org/project/{name}/",
                })
        return results, []

    def _parse_requirements(self, req_path: Path, root_path: Path) -> list[dict]:
        results: list[dict] = []
        try:
            lines = req_path.read_text(encoding="utf-8-sig").splitlines()
        except UnicodeDecodeError:
            return results

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            match = re.match(r"([A-Za-z0-9_.-]+)\s*([=><!~]+)\s*([^\s;,]+)", line)
            if match:
                name, _op, version = match.groups()
                if _op not in ("==", "==="):
                    version = f"{_op}{version}"
                results.append({
                    "name": name.lower(),
                    "group": "",
                    "version": version,
                    "ecosystem": "pypi",
                    "scope": "compile",
                    "optional": False,
                    "direct": True,
                    "source_file": rel_posix(req_path, root_path),
                    "registry_url": f"https://pypi.org/project/{name}/",
                })
            else:
                name = re.split(r"[=><!~;\s]", line)[0]
                if name:
                    results.append({
                        "name": name.lower(),
                        "group": "",
                        "version": "",
                        "ecosystem": "pypi",
                        "scope": "compile",
                        "optional": False,
                        "direct": True,
                        "source_file": rel_posix(req_path, root_path),
                        "registry_url": f"https://pypi.org/project/{name}/",
                    })
        return results

    def _parse_pyproject(self, toml_path: Path, root_path: Path) -> list[dict]:
        results: list[dict] = []
        try:
            data = tomllib.loads(toml_path.read_text(encoding="utf-8-sig"))
        except Exception:
            return results

        deps = (
            data.get("project", {}).get("dependencies", [])
            + data.get("tool", {}).get("poetry", {}).get("dependencies", [])
        )
        for dep in deps:
            if isinstance(dep, str):
                match = re.match(r"([A-Za-z0-9_.-]+)\s*([=><!~]+)\s*([^\s;,]+)", dep)
                if match:
                    name, _op, version = match.groups()
                    if _op not in ("==", "==="):
                        version = f"{_op}{version}"
                    results.append({
                        "name": name.lower(),
                        "group": "",
                        "version": version,
                        "ecosystem": "pypi",
                        "scope": "compile",
                        "optional": False,
                        "direct": True,
                        "source_file": rel_posix(toml_path, root_path),
                        "registry_url": f"https://pypi.org/project/{name}/",
                    })
        return results

    def _parse_pipfile(self, pipfile_path: Path, root_path: Path) -> list[dict]:
        results: list[dict] = []

        try:
            content = pipfile_path.read_text(encoding="utf-8-sig")
        except Exception:
            return results

        in_packages = False
        in_dev_packages = False

        for line in content.splitlines():
            stripped = line.strip()

            if stripped == "[packages]":
                in_packages = True
                in_dev_packages = False
                continue
            elif stripped == "[dev-packages]":
                in_packages = False
                in_dev_packages = True
                continue
            elif stripped.startswith("[") and (in_packages or in_dev_packages):
                in_packages = False
                in_dev_packages = False
                continue

            if not in_packages and not in_dev_packages:
                continue

            if stripped and "=" in stripped:
                kv = stripped.split("=", 1)
                name = kv[0].strip()
                value = kv[1].strip().strip('"').strip("'")

                if name.startswith("_"):
                    continue

                version = ""
                if value.startswith("{"):
                    version_match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', value)
                    if version_match:
                        version = version_match.group(1)
                elif value == "*":
                    version = ""
                elif value:
                    version = value.lstrip("=") if value.startswith("=") else value

                results.append({
                    "name": name.lower(),
                    "group": "",
                    "version": version,
                    "ecosystem": "pypi",
                    "scope": "dev" if in_dev_packages else "compile",
                    "optional": False,
                    "direct": True,
                    "source_file": rel_posix(pipfile_path, root_path),
                    "registry_url": f"https://pypi.org/project/{name}/",
                })

        return results

    def _parse_setup_py(self, setup_path: Path, root_path: Path) -> list[dict]:
        results: list[dict] = []

        try:
            content = setup_path.read_text(encoding="utf-8-sig")
        except Exception:
            return results

        patterns = [
            re.compile(r"""install_requires\s*=\s*\[(.*?)\]""", re.DOTALL),
            re.compile(r"""setup\s*\(.*?install_requires\s*=\s*\[(.*?)\]""", re.DOTALL),
        ]

        for pattern in patterns:
            match = pattern.search(content)
            if match:
                deps_block = match.group(1)
                for dep_match in re.finditer(r"""['"]([^'"]+)['"]""", deps_block):
                    dep_str = dep_match.group(1)
                    name_match = re.match(r"([A-Za-z0-9_.-]+)\s*([=><!~]+)\s*([^\s;,]+)", dep_str)
                    if name_match:
                        name, _op, version = name_match.groups()
                        if _op not in ("==", "==="):
                            version = f"{_op}{version}"
                        results.append({
                            "name": name.lower(),
                            "group": "",
                            "version": version,
                            "ecosystem": "pypi",
                            "scope": "compile",
                            "optional": False,
                            "direct": True,
                            "source_file": rel_posix(setup_path, root_path),
                            "registry_url": f"https://pypi.org/project/{name}/",
                        })
                    else:
                        name = re.split(r"[=><!~;\s]", dep_str)[0]
                        if name:
                            results.append({
                                "name": name.lower(),
                                "group": "",
                                "version": "",
                                "ecosystem": "pypi",
                                "scope": "compile",
                                "optional": False,
                                "direct": True,
                                "source_file": rel_posix(setup_path, root_path),
                                "registry_url": f"https://pypi.org/project/{name}/",
                            })
                break

        return results

    def _parse_setup_cfg(self, setup_cfg_path: Path, root_path: Path) -> list[dict]:
        results: list[dict] = []

        try:
            content = setup_cfg_path.read_text(encoding="utf-8-sig")
        except Exception:
            return results

        in_install_requires = False
        for line in content.splitlines():
            stripped = line.strip()

            if stripped == "install_requires":
                in_install_requires = True
                continue

            if stripped.startswith("[") and in_install_requires:
                in_install_requires = False
                continue

            if in_install_requires and stripped and not stripped.startswith("#"):
                dep_str = stripped.lstrip("=").strip()
                name_match = re.match(r"([A-Za-z0-9_.-]+)\s*([=><!~]+)\s*([^\s;,]+)", dep_str)
                if name_match:
                    name, _op, version = name_match.groups()
                    if _op not in ("==", "==="):
                        version = f"{_op}{version}"
                    results.append({
                        "name": name.lower(),
                        "group": "",
                        "version": version,
                        "ecosystem": "pypi",
                        "scope": "compile",
                        "optional": False,
                        "direct": True,
                        "source_file": rel_posix(setup_cfg_path, root_path),
                        "registry_url": f"https://pypi.org/project/{name}/",
                    })
                else:
                    name = re.split(r"[=><!~;\s]", dep_str)[0]
                    if name and name != "install_requires":
                        results.append({
                            "name": name.lower(),
                            "group": "",
                            "version": "",
                            "ecosystem": "pypi",
                            "scope": "compile",
                            "optional": False,
                            "direct": True,
                            "source_file": rel_posix(setup_cfg_path, root_path),
                            "registry_url": f"https://pypi.org/project/{name}/",
                        })

        return results
