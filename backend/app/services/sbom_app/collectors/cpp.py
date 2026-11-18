import re
import json
from pathlib import Path

from .base import DependencyCollector, rel_posix


class CppCollector(DependencyCollector):

    def supported_files(self) -> list[str]:
        return ["conanfile.txt", "conanfile.py", "conan.lock", "vcpkg.json", "CMakeLists.txt"]

    def collect(self, project_path: Path) -> list[dict]:
        """§5.3 pipeline: conan.lock → manifests (vcpkg/CMake are source-level).

        Conan's lockfile pins the resolved closure, so it beats the
        conanfile manifests; vcpkg and CMake evidence comes from their
        manifests regardless (no lockfile exists for them). Same-name
        packages from different ecosystems are distinct components, so the
        dedupe key carries the ecosystem prefix.
        """
        components: list[dict] = []
        seen: set[str] = set()

        # 1. Lockfile first (§5.3): conan.lock's resolved pins.
        declared = self._conan_declared_names(project_path)
        for lockfile in sorted(project_path.rglob("conan.lock")):
            for comp in self._parse_conan_lock(lockfile, project_path, declared):
                key = f"{comp['ecosystem']}:{comp['name']}"
                if key in seen:
                    continue
                seen.add(key)
                components.append(comp)

        # 2. Manifests: declared requirements per ecosystem (§5.4).
        for conanfile in sorted(project_path.rglob("conanfile.txt")):
            for comp in self._parse_conanfile(conanfile, project_path):
                key = f"{comp['ecosystem']}:{comp['name']}"
                if key in seen:
                    continue
                seen.add(key)
                components.append(comp)

        for conanfile_py in sorted(project_path.rglob("conanfile.py")):
            for comp in self._parse_conanfile_py(conanfile_py, project_path):
                key = f"{comp['ecosystem']}:{comp['name']}"
                if key in seen:
                    continue
                seen.add(key)
                components.append(comp)

        for vcpkg in sorted(project_path.rglob("vcpkg.json")):
            if ".vcpkg" in vcpkg.parts:
                continue
            for comp in self._parse_vcpkg_json(vcpkg, project_path):
                key = f"{comp['ecosystem']}:{comp['name']}"
                if key in seen:
                    continue
                seen.add(key)
                components.append(comp)

        for cmake in sorted(project_path.rglob("CMakeLists.txt")):
            if cmake.parent != project_path:
                continue
            for comp in self._parse_cmake(cmake, project_path):
                key = f"{comp['ecosystem']}:{comp['name']}"
                if key in seen:
                    continue
                seen.add(key)
                components.append(comp)

        return components

    def _conan_declared_names(self, project_path: Path) -> set[str]:
        """Names declared by the conanfile manifests — the lockfile's direct set (§5.4)."""
        declared: set[str] = set()
        for conanfile in sorted(project_path.rglob("conanfile.txt")):
            try:
                lines = conanfile.read_text(encoding="utf-8-sig").splitlines()
            except OSError:
                continue
            in_section = False
            for line in lines:
                stripped = line.strip()
                if stripped in ("[requires]", "[build_requires]", "[tool_requires]"):
                    in_section = True
                    continue
                if stripped.startswith("["):
                    in_section = False
                    continue
                if in_section and stripped and not stripped.startswith("#"):
                    name = stripped.split("/", 1)[0].strip()
                    if name:
                        declared.add(name)

        for conanfile_py in sorted(project_path.rglob("conanfile.py")):
            for comp in self._parse_conanfile_py(conanfile_py, project_path):
                if comp.get("name"):
                    declared.add(comp["name"])
        return declared

    def _parse_conan_lock(
        self, lock_path: Path, root_path: Path, declared: set[str]
    ) -> list[dict]:
        """``conan.lock``: flat ``name/version#revision`` pins (no graph, §9).

        The lockfile records no package-to-package edges, so direct flags
        come from the conanfile declarations and the rest is reported as
        locked-transitive evidence (§4) with no fabricated relationships.
        """
        try:
            data = json.loads(lock_path.read_text(encoding="utf-8-sig"))
        except (json.JSONDecodeError, UnicodeDecodeError, OSError):
            return []
        if not isinstance(data, dict):
            return []

        entries: list[str] = []
        for field in ("requires", "build_requires", "python_requires"):
            values = data.get(field)
            if isinstance(values, list):
                entries.extend(v for v in values if isinstance(v, str))

        results: list[dict] = []
        seen: set[str] = set()
        for entry in entries:
            spec = entry.split("#", 1)[0].strip()
            if "/" not in spec:
                continue
            name, _, version = spec.partition("/")
            name = name.strip()
            version = version.split("@", 1)[0].strip()
            if not name or not version or name in seen:
                continue
            seen.add(name)
            results.append({
                "name": name,
                "group": "",
                "version": version,
                "ecosystem": "conan",
                "scope": "compile",
                "optional": False,
                "direct": name in declared,
                "source_file": rel_posix(lock_path, root_path),
                "registry_url": f"https://conan.io/center/{name}",
                "hashes": [],
                "depends_on": [],
            })
        return results

    def _parse_conanfile(self, conanfile_path: Path, root_path: Path) -> list[dict]:
        results: list[dict] = []

        try:
            lines = conanfile_path.read_text(encoding="utf-8-sig").splitlines()
        except Exception:
            return results

        in_requires = False
        for line in lines:
            stripped = line.strip()
            if stripped in ("[requires]", "[build_requires]", "[tool_requires]"):
                in_requires = True
                continue
            if stripped.startswith("[") and in_requires:
                in_requires = False
                continue

            if in_requires and stripped and not stripped.startswith("#"):
                parts = stripped.split("/")
                name = parts[0].strip()
                version = parts[1].strip() if len(parts) > 1 else ""

                if "@" in version:
                    version = version.split("@")[-1]

                results.append({
                    "name": name,
                    "group": "",
                    "version": version,
                    "ecosystem": "conan",
                    "scope": "compile",
                    "optional": False,
                    "direct": True,
                    "source_file": rel_posix(conanfile_path, root_path),
                    "registry_url": f"https://conan.io/center/{name}",
                    "hashes": [],
                    "depends_on": [],
                })

        return results

    def _parse_conanfile_py(self, conanfile_path: Path, root_path: Path) -> list[dict]:
        results: list[dict] = []

        try:
            content = conanfile_path.read_text(encoding="utf-8-sig")
        except Exception:
            return results

        pattern = re.compile(r"""requires\s*\(\s*['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?\s*\)""")
        for match in pattern.finditer(content):
            name = match.group(1).strip()
            version = match.group(2) or ""
            version = version.strip()

            if "/" in name:
                parts = name.split("/")
                name = parts[0]
                version = parts[1] if len(parts) > 1 else version

            results.append({
                "name": name,
                "group": "",
                "version": version,
                "ecosystem": "conan",
                "scope": "compile",
                "optional": False,
                "direct": True,
                "source_file": rel_posix(conanfile_path, root_path),
                "registry_url": f"https://conan.io/center/{name}",
                "hashes": [],
                "depends_on": [],
            })

        return results

    def _parse_vcpkg_json(self, vcpkg_path: Path, root_path: Path) -> list[dict]:
        results: list[dict] = []

        try:
            data = json.loads(vcpkg_path.read_text(encoding="utf-8-sig"))
        except Exception:
            return results

        deps = data.get("dependencies", [])
        for dep in deps:
            if isinstance(dep, str):
                name = dep
                version = ""
            elif isinstance(dep, dict):
                name = dep.get("name", "")
                version = dep.get("version>=", dep.get("version", ""))
            else:
                continue

            if not name:
                continue

            results.append({
                "name": name,
                "group": "",
                "version": version,
                "ecosystem": "vcpkg",
                "scope": "compile",
                "optional": False,
                "direct": True,
                "source_file": rel_posix(vcpkg_path, root_path),
                "registry_url": f"https://vcpkg.io/en/packages/{name}",
                "hashes": [],
                "depends_on": [],
            })

        return results

    def _parse_cmake(self, cmake_path: Path, root_path: Path) -> list[dict]:
        results: list[dict] = []

        try:
            content = cmake_path.read_text(encoding="utf-8-sig")
        except Exception:
            return results

        find_packages = re.findall(r"find_package\s*\(\s*(\S+?)(?:\s+[\d.]+)?(?:\s+[A-Z]*)?\s*\)", content)
        fetch_content = re.findall(
            r"FetchContent_Declare\s*\(\s*(\S+)\s+URL\s+(https?://\S+)",
            content,
        )

        for name in find_packages:
            if name in ("REQUIRED", "OPTIONAL", "COMPONENTS", "QUIET", "REQUIRED"):
                continue
            results.append({
                "name": name,
                "group": "",
                "version": "",
                "ecosystem": "cmake",
                "scope": "compile",
                "optional": False,
                "direct": True,
                "source_file": rel_posix(cmake_path, root_path),
                "homepage": "",
                "repository": "",
                "hashes": [],
                "depends_on": [],
            })

        for name, url in fetch_content:
            results.append({
                "name": name,
                "group": "",
                "version": "",
                "ecosystem": "cmake",
                "scope": "compile",
                "optional": False,
                "direct": True,
                "source_file": rel_posix(cmake_path, root_path),
                "download_url": url,
                "hashes": [],
                "depends_on": [],
            })

        return results
