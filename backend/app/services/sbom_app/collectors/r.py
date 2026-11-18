"""R collector — static parsing of ``renv.lock`` and ``DESCRIPTION``.

Static only: no ``renv::restore()``/Rscript invocation. ``renv.lock`` pins the
installed set; ``DESCRIPTION`` declares which of those are direct and which
are Suggests-only (dev) evidence (§5).
"""

import json
import re
from pathlib import Path

from .base import DependencyCollector, path_ignored, read_text_safe, rel_posix

_DESC_FIELDS = re.compile(
    r"^(?P<field>Depends|Imports|LinkingTo|Suggests):[ \t]*(?P<value>.*(?:\r?\n[ \t]+.*)*)",
    re.MULTILINE,
)
_HEX64 = re.compile(r"[0-9a-f]{64}", re.IGNORECASE)


def _declared_from_description(path: Path) -> dict[str, dict]:
    """Package name -> {scope, version} from DESCRIPTION.

    Suggests-only entries are dev evidence; the parenthesized constraint
    (``mime (>= 1.0.0)``) is kept verbatim as the declared version.
    """
    try:
        text = read_text_safe(path)
    except (OSError, UnicodeDecodeError):
        return {}
    declared: dict[str, dict] = {}
    matches = list(_DESC_FIELDS.finditer(text))
    for match in matches:
        field = match.group("field")
        scope = "dev" if field == "Suggests" else "compile"
        for item in match.group("value").replace("\n", " ").split(","):
            name = re.split(r"\s*\(", item.strip())[0].strip()
            if not name or name == "R":
                continue
            paren = re.search(r"\(([^)]*)\)", item)
            version = paren.group(1).strip() if paren else ""
            entry = {"scope": scope, "version": version}
            if scope == "compile" or name not in declared:
                declared[name] = entry
    return declared


class RCollector(DependencyCollector):

    def supported_files(self) -> list[str]:
        return ["renv.lock", "DESCRIPTION"]

    def collect(self, project_path: Path) -> list[dict]:
        declared: dict[str, dict] = {}
        for desc in sorted(project_path.rglob("DESCRIPTION")):
            if path_ignored(desc.relative_to(project_path)):
                continue
            for name, entry in _declared_from_description(desc).items():
                if entry["scope"] == "compile" or name not in declared:
                    declared[name] = entry

        components: list[dict] = []
        seen: set[str] = set()
        for lock in sorted(project_path.rglob("renv.lock")):
            if path_ignored(lock.relative_to(project_path)):
                continue
            for comp in self._parse_lock(lock, project_path, declared):
                key = comp["name"]
                if key in seen:
                    continue
                seen.add(key)
                components.append(comp)
        if components:
            return components

        # No renv.lock: DESCRIPTION declarations are direct-only evidence (§5),
        # carrying their raw declared constraints.
        for name, entry in declared.items():
            components.append({
                "name": name,
                "group": "",
                "version": entry["version"],
                "ecosystem": "r",
                "scope": entry["scope"],
                "direct": True,
                "source_file": "DESCRIPTION",
                "hashes": [],
                "depends_on": [],
                "registry_url": f"https://cran.r-project.org/package={name}",
            })
        return components

    def _parse_lock(
        self, lock: Path, root_path: Path, declared: dict[str, dict]
    ) -> list[dict]:
        try:
            data = json.loads(read_text_safe(lock))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return []
        if not isinstance(data, dict):
            return []
        packages = data.get("Packages")
        if not isinstance(packages, dict):
            return []
        repositories = {}
        repos = (data.get("R") or {}).get("Repositories")
        if isinstance(repos, list):
            for repo in repos:
                if isinstance(repo, dict) and isinstance(repo.get("Name"), str):
                    repositories[repo["Name"]] = str(repo.get("URL") or "")
        source = rel_posix(lock, root_path)

        results: list[dict] = []
        for key, rec in packages.items():
            if not isinstance(rec, dict):
                continue
            pkg = rec.get("Package") if isinstance(rec.get("Package"), str) else str(key)
            if pkg == "R":
                continue
            version = str(rec.get("Version") or "")
            origin = str(rec.get("Source") or "")
            comp = self._component(pkg, version, origin, rec, repositories, source)
            if comp is None:
                continue
            entry = declared.get(pkg)
            comp["direct"] = entry is not None
            comp["scope"] = entry["scope"] if entry else "compile"
            results.append(comp)
        return results

    @staticmethod
    def _component(
        pkg: str, version: str, origin: str, rec: dict,
        repositories: dict[str, str], source: str,
    ) -> dict | None:
        if origin == "Local":
            # Local installs are project code, not a collected dependency.
            return None
        comp = {
            "name": pkg,
            "group": "",
            "version": version,
            "ecosystem": "r",
            "scope": "compile",
            "direct": False,
            "source_file": source,
            "hashes": [],
            "depends_on": [],
            "registry_url": "",
        }
        if origin == "GitHub" or origin == "GitLab" or origin == "Bitbucket":
            user = str(rec.get("RemoteUsername") or "")
            repo = str(rec.get("RemoteRepo") or "")
            if not repo:
                return None
            comp["name"] = repo
            comp["group"] = user
            comp["purl_type"] = "github" if origin == "GitHub" else "generic"
            if origin != "GitHub":
                comp["purl_qualifier"] = origin.lower()
            comp["registry_url"] = (
                f"https://github.com/{user}/{repo}" if user and origin == "GitHub" else ""
            )
            if not version:
                sha = str(rec.get("RemoteSha") or "")
                comp["version"] = sha
        else:
            repository = str(rec.get("Repository") or "CRAN")
            comp["registry_url"] = (
                f"https://cran.r-project.org/package={pkg}"
                if repository in ("", "CRAN")
                else ""
            )
            url = repositories.get(repository, "")
            if url:
                comp["registry_url"] = f"{url.rstrip('/')}/web/packages/{pkg}/"
        integrity = str(rec.get("hash") or "")
        if _HEX64.fullmatch(integrity):
            comp["hashes"] = [{"alg": "SHA-256", "content": integrity.lower()}]
        return comp
