import re
import xml.etree.ElementTree as ET
from pathlib import Path

import httpx

from .base import DependencyCollector, read_text_safe, rel_posix

MAVEN_NS = "{http://maven.apache.org/POM/4.0.0}"


def _find(el, tag: str):
    """Namespace-tolerant: real POMs declare the xmlns, hand-written ones often don't.

    An empty but present element (e.g. ``<optional></optional>``) is falsy, so
    the match must be checked against ``None`` rather than truthiness.
    """
    if el is None:
        return None
    found = el.find(f"{MAVEN_NS}{tag}")
    if found is None:
        found = el.find(tag)
    return found


def _findall(el, tag: str) -> list:
    if el is None:
        return []
    return el.findall(f"{MAVEN_NS}{tag}") or el.findall(tag)


class MavenCollector(DependencyCollector):

    def supported_files(self) -> list[str]:
        return ["pom.xml"]

    def collect(self, project_path: Path) -> tuple[list[dict], list[dict]]:
        """pom.xml first (file-level evidence), then ``mvn dependency:tree`` for transitive depth."""
        components: list[dict] = []
        edges: list[dict] = []
        roots = self._find_maven_roots(project_path)
        for pom_dir in roots:
            comps, pom_edges = self._parse_pom(pom_dir / "pom.xml", project_path)
            components.extend(comps)
            edges.extend(pom_edges)

        tree_components: list[dict] = []
        if self._command_exists("mvn"):
            for pom_dir in roots[:1]:
                output = self._run_cli(
                    ["mvn", "-B", "dependency:tree"],
                    cwd=pom_dir,
                    timeout=180,
                )
                if not output:
                    continue
                # Text output carries the tree depth; XML (when a future plugin
                # version emits it) is a flat fallback so components are never
                # lost just because the tree grammar shifted.
                parsed = self._parse_dependency_tree_text(
                    output, pom_dir, project_path, set()
                )
                if not parsed and "<artifact" in output:
                    parsed = self._parse_dependency_tree_xml(
                        output, pom_dir, project_path, set()
                    )
                tree_components.extend(parsed)

        components.extend(tree_components)
        if tree_components:
            self._reconcile_unresolved(components, edges, tree_components)
        return components, edges

    def _reconcile_unresolved(
        self,
        components: list[dict],
        edges: list[dict],
        tree_components: list[dict],
    ) -> None:
        """Adopt tree versions for pom sightings whose ${property}/BOM
        placeholders the local POM could not resolve, and rewrite edge refs
        so relationships point at the resolved purls."""
        resolved = {
            f"{c.get('group', '')}:{c.get('name', '')}": c
            for c in tree_components
        }
        replacements: dict[str, str] = {}
        for comp in components:
            if comp.get("version") != "unresolved":
                continue
            hit = resolved.get(f"{comp.get('group', '')}:{comp.get('name', '')}")
            if not hit:
                continue
            group = comp.get("group", "")
            name = comp.get("name", "")
            version = hit["version"]
            replacements[f"pkg:maven/{group}/{name}@unresolved?type=jar"] = (
                f"pkg:maven/{group}/{name}@{version}?type=jar"
            )
            comp["version"] = version
            comp["homepage"] = f"https://central.sonatype.com/artifact/{group}/{name}/{version}"
            comp["repository"] = (
                f"https://repo1.maven.org/maven2/{group.replace('.', '/')}/{name}/{version}/"
            )
            comp["hashes"] = self._fetch_maven_hash(group, name, version)

        if not replacements:
            return
        for edge in edges:
            edge["ref"] = replacements.get(edge.get("ref", ""), edge.get("ref", ""))
            edge["dependsOn"] = [
                replacements.get(ref, ref) for ref in edge.get("dependsOn") or []
            ]

    def _find_maven_roots(self, project_path: Path) -> list[Path]:
        roots = []
        for pom in project_path.rglob("pom.xml"):
            if "target" not in pom.parts and "node_modules" not in pom.parts:
                roots.append(pom.parent)
        return sorted(roots)[:25]

    def _parse_dependency_tree_xml(
        self, xml_output: str, pom_dir: Path, root_path: Path, seen: set[str]
    ) -> list[dict]:
        results: list[dict] = []

        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError:
            return results

        for artifact in root.iter("artifact"):
            group = artifact.get("groupId", "")
            name = artifact.get("artifactId", "")
            version = artifact.get("version", "")
            scope = artifact.get("scope", "compile")
            optional = artifact.get("optional", "false") == "true"

            dep_key = f"{group}:{name}:{version}"
            if dep_key in seen:
                continue
            seen.add(dep_key)

            if not group or not name or not version:
                continue

            hashes = self._fetch_maven_hash(group, name, version)

            results.append({
                "name": name,
                "group": group,
                "version": version,
                "ecosystem": "maven",
                "scope": scope,
                "optional": optional,
                "direct": False,
                "source_file": "dependency:tree",
                "registry_url": f"https://central.sonatype.com/artifact/{group}/{name}/{version}",
                "hashes": hashes,
                "depends_on": [],
            })

        return results

    def _parse_dependency_tree_text(
        self, text_output: str, pom_dir: Path, root_path: Path, seen: set[str]
    ) -> list[dict]:
        """Parse `mvn dependency:tree` text output into components + edges.

        Indentation carries the graph: a child attaches to the last line at a
        shallower depth. Level 0 lines are the module's direct dependencies;
        every deeper level is transitive (§5).
        """
        results: list[dict] = []
        by_key: dict[str, dict] = {}
        # Prefix grammar: `+-`, `\-`, `|  +-`, `   \-`, `|  |  \-` ... — the
        # backslash branch indents with spaces (no pipes), so depth comes from
        # prefix width: level 0 is 2 chars, each level adds 3.
        pattern = re.compile(
            r"^\[INFO\]\s([|\\ ]*\+?-)\s+(\S+?):(\S+?):(\S+?):(\S+?)"
            r"(?::(\S+))?(?::(\S+))?\s*(?:\([^)]*\))?\s*$"
        )

        parent_stack: list[tuple[int, str]] = []

        for line in text_output.splitlines():
            match = pattern.match(line)
            if not match:
                continue

            prefix = match.group(1)
            group = match.group(2)
            name = match.group(3)
            artifact_type = match.group(4)
            version = match.group(5)
            scope = match.group(6) or "compile"

            if not group or not name or not version:
                continue

            depth = max((len(prefix) - 2) // 3, 0)
            while parent_stack and parent_stack[-1][0] >= depth:
                parent_stack.pop()

            dep_key = f"{group}:{name}:{version}"
            purl = f"pkg:maven/{group}/{name}@{version}?type={artifact_type}"

            comp = by_key.get(dep_key)
            if comp is None:
                hashes = self._fetch_maven_hash(group, name, version)
                comp = {
                    "name": name,
                    "group": group,
                    "version": version,
                    "ecosystem": "maven",
                    "scope": scope,
                    "optional": False,
                    "direct": depth == 0,
                    "source_file": "dependency:tree",
                    "registry_url": f"https://central.sonatype.com/artifact/{group}/{name}/{version}",
                    "hashes": hashes,
                    "depends_on": [],
                }
                results.append(comp)
                by_key[dep_key] = comp
                seen.add(dep_key)
            elif depth == 0:
                comp["direct"] = True

            if parent_stack:
                parent = by_key.get(parent_stack[-1][1])
                if parent is not None and parent is not comp and purl not in parent["depends_on"]:
                    parent["depends_on"].append(purl)

            parent_stack.append((depth, dep_key))

        return results

    def _parse_pom(self, pom_path: Path, root_path: Path) -> tuple[list[dict], list[dict]]:
        results: list[dict] = []
        edges: list[dict] = []
        try:
            root = ET.fromstring(read_text_safe(pom_path))
        except (ET.ParseError, UnicodeDecodeError, OSError):
            return results, edges

        properties = self._extract_properties(root)
        parent = self._extract_parent(root)
        managed_versions = self._extract_dependency_management(root, properties)

        project_group = (parent or {}).get("groupId", "") or self._text(root, "groupId") or ""
        project_artifact = self._text(root, "artifactId") or ""
        project_version = self._text(root, "version") or (parent or {}).get("version", "")
        project_purl = (
            f"pkg:maven/{project_group}/{project_artifact}@{project_version}?type=jar"
            if project_group and project_artifact and project_version
            else ""
        )

        direct_purls: list[str] = []
        for dep in _findall(_find(root, "dependencies"), "dependency"):
            group_id = self._text(dep, "groupId") or ""
            artifact_id = self._text(dep, "artifactId") or ""
            version_raw = self._text(dep, "version") or ""
            scope = self._text(dep, "scope") or "compile"
            optional = (self._text(dep, "optional") or "false") == "true"

            if not group_id and parent:
                group_id = parent.get("groupId", "")
            version = self._resolve_property(version_raw, properties)
            if not version or version.startswith("${"):
                version = managed_versions.get(f"{group_id}:{artifact_id}", "")

            if not group_id or not artifact_id:
                continue

            if not version or version.startswith("${"):
                version = "unresolved"

            dep_homepage = f"https://central.sonatype.com/artifact/{group_id}/{artifact_id}/{version}"
            dep_repo = f"https://repo1.maven.org/maven2/{group_id.replace('.', '/')}/{artifact_id}/{version}/"
            dep_purl = f"pkg:maven/{group_id}/{artifact_id}@{version}?type=jar"
            direct_purls.append(dep_purl)

            results.append({
                "name": artifact_id,
                "group": group_id,
                "version": version,
                "ecosystem": "maven",
                "scope": scope,
                "optional": optional,
                "direct": True,
                "source_file": rel_posix(pom_path, root_path),
                "homepage": dep_homepage,
                "repository": dep_repo,
                "depends_on": [],
            })

        if project_purl and direct_purls:
            edges.append({"ref": project_purl, "dependsOn": direct_purls})

        return results, edges

    def _extract_dependency_management(self, root, properties: dict[str, str]) -> dict[str, str]:
        managed: dict[str, str] = {}
        for dep in _findall(_find(_find(root, "dependencyManagement"), "dependencies"), "dependency"):
            group_id = self._text(dep, "groupId") or ""
            artifact_id = self._text(dep, "artifactId") or ""
            version = self._resolve_property(self._text(dep, "version") or "", properties)
            if group_id and artifact_id and version:
                managed[f"{group_id}:{artifact_id}"] = version
        return managed

    def _extract_properties(self, root) -> dict[str, str]:
        props: dict[str, str] = {}
        props_el = _find(root, "properties")
        if props_el is not None:
            for child in props_el:
                tag = child.tag.replace(MAVEN_NS, "")
                if child.text:
                    props[tag] = child.text.strip()
        return props

    def _extract_parent(self, root) -> dict[str, str] | None:
        parent_el = _find(root, "parent")
        if parent_el is None:
            return None
        return {
            "groupId": self._text(parent_el, "groupId") or "",
            "artifactId": self._text(parent_el, "artifactId") or "",
            "version": self._text(parent_el, "version") or "",
        }

    def _resolve_property(self, value: str, properties: dict[str, str]) -> str:
        if not value or not value.startswith("${"):
            return value
        prop_name = value.strip("${}")
        return properties.get(prop_name, value)

    def _fetch_maven_hash(self, group: str, artifact: str, version: str) -> list[dict]:
        hashes = []
        sha1_path = self._find_local_sha1(group, artifact, version)
        if sha1_path:
            try:
                sha1_value = sha1_path.read_text(encoding="utf-8-sig").strip()
                if sha1_value and len(sha1_value) == 40:
                    hashes.append({"alg": "SHA-1", "content": sha1_value})
            except Exception:
                pass

        if not hashes:
            try:
                url = f"https://repo1.maven.org/maven2/{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}.sha1"
                resp = httpx.get(url, timeout=5.0)
                if resp.status_code == 200:
                    sha1_value = resp.text.strip()
                    if sha1_value and len(sha1_value) == 40:
                        hashes.append({"alg": "SHA-1", "content": sha1_value})
            except Exception:
                pass

        return hashes

    def _find_local_sha1(self, group: str, artifact: str, version: str) -> Path | None:
        m2_path = Path.home() / ".m2" / "repository" / group.replace(".", "/") / artifact / version
        sha1_file = m2_path / f"{artifact}-{version}.jar.sha1"
        if sha1_file.exists():
            return sha1_file
        return None

    @staticmethod
    def _text(el, tag: str) -> str | None:
        if el is None:
            return None
        child = el.find(f"{MAVEN_NS}{tag}")
        if child is None:
            child = el.find(tag)
        return child.text.strip() if child is not None and child.text else None
