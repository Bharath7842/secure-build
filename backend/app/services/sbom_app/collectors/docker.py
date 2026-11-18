"""Docker collector — static parsing of ``Dockerfile`` and compose files.

Static only: no image pulls, no container runtime (per scope constraints).
Resolves ``FROM`` stage aliases so only real base images become components.
Build relationships are read from the files themselves: a stage's
``COPY --from=<stage|image>`` links that stage's base image to the source
image, and compose ``depends_on`` links one service's image to another's.
"""

import re
from pathlib import Path

from .base import DependencyCollector, purl_for, rel_posix

try:
    import yaml
except ImportError:  # pragma: no cover - exercised only without PyYAML
    yaml = None

_FROM = re.compile(
    r"""^\s*FROM\s+(?:--platform=\S+\s+)?(?P<image>\S+)(?:\s+AS\s+(?P<stage>\S+))?\s*$""",
    re.I,
)
_COPY = re.compile(r"^\s*COPY\s+", re.I)
_COPY_FROM = re.compile(r"--from(?:=(?P<eq>\S+)|\s+(?P<sp>\S+))")
_BUILD_ARG = re.compile(r"""^\s*ARG\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>\S+)\s*$""", re.M)
_COMPOSE_IMAGE = re.compile(r"""^\s*image:\s*['"]?(?P<image>[^\s'"]+)['"]?\s*$""", re.M)
_VAR = re.compile(r"\$\{(?P<name>[A-Za-z_][A-Za-z0-9_]*)\}|\$(?P<name2>[A-Za-z_][A-Za-z0-9_]*)")

if yaml is not None:

    class _LenientLoader(yaml.SafeLoader):
        """SafeLoader that tolerates custom tags such as compose ``!reset``."""

    def _unknown_tag(loader, _suffix, node):
        if isinstance(node, yaml.MappingNode):
            return loader.construct_mapping(node, deep=True)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node, deep=True)
        return loader.construct_scalar(node)

    _LenientLoader.add_multi_constructor("!", _unknown_tag)
    _YAML_LOADER = _LenientLoader
else:  # pragma: no cover
    _YAML_LOADER = None


def _split_image(image: str) -> tuple[str, str, str]:
    """`registry/repo/name:tag` -> (namespace, name, tag)."""
    image = image.strip()
    tag = "latest"
    if "@" in image:
        image = image.split("@", 1)[0]
    if ":" in image and image.rfind(":") > image.rfind("/"):
        image, tag = image.rsplit(":", 1)
    parts = image.split("/")
    if len(parts) == 1:
        return "library", parts[0], tag
    if len(parts) == 2:
        return parts[0], parts[1], tag
    return "/".join(parts[:-1]), parts[-1], tag


def _image_component(image: str, source: str) -> dict:
    namespace, name, tag = _split_image(image)
    return {
        "name": name,
        "group": namespace,
        "version": tag,
        "ecosystem": "docker",
        "type": "container",
        "scope": "runtime",
        "direct": True,
        "source_file": source,
        "hashes": [],
        "depends_on": [],
        "registry_url": f"https://hub.docker.com/r/{namespace}/{name}"
        if namespace != "library"
        else f"https://hub.docker.com/_/{name}",
    }


def _image_key(comp: dict) -> str:
    return f"{comp.get('group', '')}/{comp.get('name', '')}:{comp.get('version', '')}"


def _logical_lines(content: str) -> list[str]:
    """Join backslash-continued physical lines into logical instructions."""
    out: list[str] = []
    pending = ""
    for raw in content.splitlines():
        line = raw.rstrip()
        pending = f"{pending} {line.lstrip()}" if pending else line
        if pending.endswith("\\"):
            pending = pending[:-1].rstrip()
            continue
        if pending.strip():
            out.append(pending)
        pending = ""
    if pending.strip():
        out.append(pending)
    return out


def _service_names(depends_on) -> list[str]:
    """Service names from compose ``depends_on`` (scalar, list or map form)."""
    if isinstance(depends_on, str):
        return [depends_on]
    if isinstance(depends_on, dict):
        return [str(k) for k in depends_on]
    if isinstance(depends_on, list):
        return [v for v in depends_on if isinstance(v, str)]
    return []


class DockerCollector(DependencyCollector):

    def supported_files(self) -> list[str]:
        return ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"]

    def collect(self, project_path: Path) -> tuple[list[dict], list[dict]]:
        merged: dict[str, dict] = {}
        pairs: list[tuple[str, str]] = []

        for dockerfile in sorted(project_path.rglob("Dockerfile*")):
            if not dockerfile.is_file():
                continue
            comps, file_pairs = self._parse_dockerfile(dockerfile, project_path)
            for comp in comps:
                merged.setdefault(_image_key(comp), comp)
            pairs.extend(file_pairs)

        for compose in sorted(
            list(project_path.rglob("docker-compose*.yml"))
            + list(project_path.rglob("docker-compose*.yaml"))
        ):
            comps, file_pairs = self._parse_compose(compose, project_path)
            for comp in comps:
                merged.setdefault(_image_key(comp), comp)
            pairs.extend(file_pairs)

        for parent_key, child_key in pairs:
            parent = merged.get(parent_key)
            child = merged.get(child_key)
            if parent is None or child is None or parent is child:
                continue
            purl = purl_for(child)
            if purl and purl not in parent["depends_on"]:
                parent["depends_on"].append(purl)

        return list(merged.values()), []

    def _parse_dockerfile(
        self, dockerfile: Path, root_path: Path
    ) -> tuple[list[dict], list[tuple[str, str]]]:
        try:
            content = dockerfile.read_text(encoding="utf-8-sig")
        except OSError:
            return [], []

        args = {m.group("name"): m.group("value") for m in _BUILD_ARG.finditer(content)}
        rel = rel_posix(dockerfile, root_path)

        by_key: dict[str, dict] = {}
        stages: dict[str, str] = {}      # stage alias (lower) -> image key
        stage_keys: list[str] = []       # image key per FROM, in order (§9 stages)
        current = ""
        pairs: list[tuple[str, str]] = []

        def substitute(value: str) -> str:
            return _VAR.sub(
                lambda m: args.get(m.group("name") or m.group("name2") or "", ""),
                value,
            )

        def add_image(image: str) -> str:
            if "$" in image or image.startswith("/"):
                return ""
            namespace, name, tag = _split_image(image)
            if not name:
                return ""
            key = f"{namespace}/{name}:{tag}"
            if key not in by_key:
                by_key[key] = _image_component(image, rel)
            return key

        for instruction in _logical_lines(content):
            from_match = _FROM.match(instruction)
            if from_match:
                image = substitute(from_match.group("image"))
                alias = from_match.group("stage")
                if not image or image.startswith("$"):
                    key = ""
                elif image.lower() in stages:
                    # Stage alias: the same underlying image, never a new one.
                    key = stages[image.lower()]
                else:
                    key = add_image(image)
                if alias:
                    stages[alias.lower()] = key
                stage_keys.append(key)
                current = key
                continue

            if not _COPY.match(instruction):
                continue
            from_match = _COPY_FROM.search(instruction)
            if not from_match or not current:
                continue
            src = substitute(from_match.group("eq") or from_match.group("sp") or "")
            target = ""
            if src.isdigit():
                index = int(src)
                if index < len(stage_keys):
                    target = stage_keys[index]
            elif src.lower() in stages:
                target = stages[src.lower()]
            elif src and not src.startswith("$"):
                # ``COPY --from=<image>`` pulls a named image (docker resolves
                # unknown stage names as image references too).
                target = add_image(src)
            if target and target != current:
                pairs.append((current, target))

        return list(by_key.values()), pairs

    def _parse_compose(
        self, compose_path: Path, root_path: Path
    ) -> tuple[list[dict], list[tuple[str, str]]]:
        try:
            content = compose_path.read_text(encoding="utf-8-sig")
        except OSError:
            return [], []

        rel = rel_posix(compose_path, root_path)
        services = self._compose_services(content)

        if services:
            by_key: dict[str, dict] = {}
            images: dict[str, str] = {}

            for service, spec in services.items():
                if not isinstance(spec, dict):
                    continue
                image = spec.get("image")
                if not isinstance(image, str) or not image.strip():
                    # build-only services reference no image name (§7).
                    continue
                image = image.strip().strip("'\"")
                if "$" in image:
                    continue
                namespace, name, tag = _split_image(image)
                if not name:
                    continue
                key = f"{namespace}/{name}:{tag}"
                if key not in by_key:
                    by_key[key] = _image_component(image, rel)
                images[str(service)] = key

            if images:
                pairs: list[tuple[str, str]] = []
                for service, spec in services.items():
                    if not isinstance(spec, dict):
                        continue
                    parent = images.get(str(service))
                    if not parent:
                        continue
                    for dep in _service_names(spec.get("depends_on")):
                        child = images.get(dep)
                        if child and child != parent:
                            pairs.append((parent, child))
                return list(by_key.values()), pairs

        # No structured services found (or no PyYAML): keep the historical
        # evidence — every ``image:`` line in the file — without edges.
        results: list[dict] = []
        seen: set[str] = set()
        for match in _COMPOSE_IMAGE.finditer(content):
            image = match.group("image")
            if "$" in image:
                continue
            namespace, name, tag = _split_image(image)
            if not name:
                continue
            key = f"{namespace}/{name}:{tag}"
            if key in seen:
                continue
            seen.add(key)
            results.append(_image_component(image, rel))
        return results, []

    @staticmethod
    def _compose_services(content: str) -> dict | None:
        """Compose ``services`` mapping (v2 ``services:`` or legacy v1 layout)."""
        if yaml is None:
            return None
        try:
            data = yaml.load(content, Loader=_YAML_LOADER)
        except Exception:
            return None
        if not isinstance(data, dict):
            return None
        services = data.get("services")
        if isinstance(services, dict):
            return services
        # Compose v1: the top level is the services mapping itself.
        legacy = {
            key: value
            for key, value in data.items()
            if isinstance(value, dict)
            and not str(key).startswith("x-")
            and ("image" in value or "depends_on" in value)
        }
        return legacy or None
