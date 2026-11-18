import base64
import binascii
import json
import logging
import re
import shutil
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path

from ..sbom.purl import generate_purl, purl_identity

logger = logging.getLogger("sbom.collectors")

# Directories that hold installed dependencies or build output rather than
# project manifests, even when a collector ``rglob`` would reach them.
_SKIP_DIR_PARTS = frozenset({
    ".git", "node_modules", "vendor", "lib", "local", ".stack-work",
    "dist-newstyle", "elm-stuff", "_build", ".venv", "venv", "Pods",
    ".bundle", "bower_components",
})


def path_ignored(rel: Path) -> bool:
    """True when any directory of a repo-relative path is an install/build dir."""
    return any(part in _SKIP_DIR_PARTS for part in rel.parts[:-1])

_SRI_ALGORITHMS = {
    "md5": ("MD5", 32),
    "sha1": ("SHA-1", 40),
    "sha256": ("SHA-256", 64),
    "sha384": ("SHA-384", 96),
    "sha512": ("SHA-512", 128),
}


def read_text_safe(path: Path) -> str:
    """Read a manifest/lockfile tolerating a UTF-8 BOM (common on Windows)."""
    return path.read_text(encoding="utf-8-sig")


def rel_posix(path: Path, root: Path) -> str:
    """Repo-relative evidence path with POSIX separators (§5.8/§6)."""
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = Path(path.name)
    return rel.as_posix()


def sri_hashes(integrity: str) -> list[dict]:
    """Decode an SRI digest (``sha512-<base64>``) into CycloneDX hex hashes.

    CycloneDX requires lowercase hex of an exact length; anything that cannot be
    decoded to that length is dropped rather than emitted as an invalid hash.
    """
    if not integrity:
        return []
    algorithm, _, digest = str(integrity).partition("-")
    known = _SRI_ALGORITHMS.get(algorithm.lower())
    if not known:
        return []
    name, hex_length = known
    digest = digest.strip()
    if not digest:
        return []

    if re.fullmatch(rf"[a-fA-F0-9]{{{hex_length}}}", digest):
        return [{"alg": name, "content": digest.lower()}]

    padded = digest + "=" * (-len(digest) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        try:
            raw = base64.urlsafe_b64decode(padded)
        except (binascii.Error, ValueError):
            return []

    if len(raw) * 2 != hex_length:
        return []
    return [{"alg": name, "content": raw.hex()}]


def jsonc_loads(text: str) -> dict:
    """Parse JSONC: JSON with ``//``/``/*`` comments and trailing commas.

    Both passes are string-aware so URLs (``https://…``) stay intact.
    """
    out: list[str] = []
    i, n, in_str = 0, len(text), False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1

    cleaned = "".join(out)
    out = []
    i, n, in_str = 0, len(cleaned), False
    while i < n:
        ch = cleaned[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(cleaned[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if ch == ",":
            j = i + 1
            while j < n and cleaned[j] in " \t\r\n":
                j += 1
            if j < n and cleaned[j] in "}]":
                i += 1
                continue
        out.append(ch)
        i += 1
    return json.loads("".join(out))


def purl_for(component: dict) -> str:
    """Canonical purl for a collected component.

    Mirrors the purl assignment done later by the dependency node, so
    ``depends_on`` entries written during collection always resolve.
    """
    return generate_purl(component)


def link_dependencies(components: list[dict]) -> None:
    """Resolve each component's ``_dep_names`` into ``depends_on`` purls (§5.6).

    Collectors record child dependency *identities* while parsing (a bare name
    from a lockfile, or a name + exact version when the lockfile provides one).
    Once every component of the ecosystem is known, identities are resolved to
    the purls of components that were actually collected — a child that cannot
    be resolved is dropped rather than emitted as a dangling reference (§13).
    """
    index: dict[str, list[dict]] = {}
    for comp in components:
        name = comp.get("name", "")
        if name:
            index.setdefault(name, []).append(comp)

    for comp in components:
        specs = comp.pop("_dep_names", None)
        if specs is None:
            continue
        purls: list[str] = []
        for spec in specs:
            if isinstance(spec, str):
                name, version = spec, ""
            else:
                name = spec.get("name", "")
                version = spec.get("version", "")
            for candidate in index.get(name, []):
                if candidate is comp:
                    continue
                if version and candidate.get("version", "") != version:
                    continue
                purl = purl_for(candidate)
                if purl and purl not in purls:
                    purls.append(purl)
        comp["depends_on"] = purls


def _fold_identity(ident: tuple[str, str, str, str]) -> tuple[str, str, str, str]:
    return (ident[0], ident[1].casefold(), ident[2].casefold(), ident[3])


def prefer_static_or_cli(static: list[dict], cli: list[dict]) -> list[dict]:
    """Source arbitration for one ecosystem (§5.3).

    The approved pipeline is lockfile → manifest → CLI, with a CLI consulted
    only when the static evidence lacks transitive depth:

    - a CLI result replaces static evidence only when it carries dependency
      edges the static sources do not have (real depth beats declared-only);
    - when the static sources produced nothing, a flat CLI result is the
      honest fallback (direct-only evidence, reported with an explicit
      transitive-depth warning downstream);
    - otherwise the static evidence wins — a manifest never gets preempted
      by a flat listing that adds nothing.
    """
    if not static:
        return cli
    if any(c.get("depends_on") for c in cli) and not any(
        c.get("depends_on") for c in static
    ):
        return cli
    return static


def canonicalize_relationships(components: list[dict], edges: list[dict]) -> None:
    """Rewrite relationship refs to the canonical purl of the component they
    identify, and drop child refs no collected component matches (§13).

    Collectors build refs while parsing (raw lockfile keys, CLI output,
    enrichment tools) and those strings are not always byte-identical to
    the canonical purl assigned downstream — an unencoded npm scope,
    differing percent-encoding, or letter case. An edge parent that
    identifies no component is preserved: it is the project root, which
    the CycloneDX builder materializes as a component (§9). A child that
    cannot be resolved to exactly one component is dropped rather than
    emitted as a dangling reference.
    """
    known: set[str] = set()
    by_ident: dict[tuple, list[str]] = {}
    by_fold: dict[tuple, list[str]] = {}
    by_name: dict[tuple, list[str]] = {}

    for comp in components:
        purl = comp.get("purl") or ""
        if not purl:
            continue
        known.add(purl)
        ident = purl_identity(purl)
        if not ident[2]:
            continue
        folded = _fold_identity(ident)
        for table, key in ((by_ident, ident), (by_fold, folded),
                           (by_name, folded[:3])):
            bucket = table.setdefault(key, [])
            if purl not in bucket:
                bucket.append(purl)

    def resolve(ref: str) -> str | None:
        if not ref:
            return None
        if ref in known:
            return ref
        ident = purl_identity(ref)
        if not ident[2]:
            return None
        if not ident[3]:
            bucket = by_name.get(_fold_identity(ident)[:3])
            if not bucket:
                return None
            return bucket[0] if len(bucket) == 1 else None
        for table, key in ((by_ident, ident), (by_fold, _fold_identity(ident))):
            bucket = table.get(key)
            if bucket:
                return bucket[0] if len(bucket) == 1 else None
        return None

    for comp in components:
        for field in ("depends_on", "peer_depends_on"):
            specs = comp.get(field)
            if not isinstance(specs, list):
                continue
            resolved: list[str] = []
            for ref in specs:
                if isinstance(ref, str):
                    purl = resolve(ref)
                    if purl and purl not in resolved:
                        resolved.append(purl)
            comp[field] = resolved

    for edge in edges:
        if not isinstance(edge, dict):
            continue
        parent = resolve(edge.get("ref") or "")
        if parent:
            edge["ref"] = parent
        children: list[str] = []
        for ref in edge.get("dependsOn") or []:
            if isinstance(ref, str):
                purl = resolve(ref)
                if purl and purl not in children:
                    children.append(purl)
        edge["dependsOn"] = children


class DependencyCollector(ABC):

    @abstractmethod
    def collect(self, project_path: Path) -> list[dict] | tuple[list[dict], list[dict]]:
        pass

    @abstractmethod
    def supported_files(self) -> list[str]:
        pass

    def _command_exists(self, cmd: str) -> bool:
        return shutil.which(cmd) is not None

    def _run_cli(
        self,
        cmd: list[str],
        cwd: Path,
        timeout: int = 120,
    ) -> str | None:
        resolved = [shutil.which(cmd[0]) or cmd[0], *cmd[1:]]
        try:
            result = subprocess.run(
                resolved,
                cwd=str(cwd),
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout
            if result.returncode != 0:
                tail = (result.stderr or "").strip().splitlines()[-1:]
                logger.warning(
                    "Command exited with code %s: %s%s",
                    result.returncode,
                    " ".join(cmd),
                    f" — {tail[0]}" if tail else "",
                )
            else:
                logger.warning("Command produced no output: %s", " ".join(cmd))
        except subprocess.TimeoutExpired:
            logger.warning("Command timed out: %s", " ".join(cmd))
        except FileNotFoundError:
            logger.warning("Command not found: %s", cmd[0])
        except Exception as e:
            logger.warning("Command failed: %s: %s", " ".join(cmd), e)
        return None

    def _run_cli_json(
        self,
        cmd: list[str],
        cwd: Path,
        timeout: int = 120,
    ) -> dict | None:
        import json
        output = self._run_cli(cmd, cwd, timeout)
        if output:
            try:
                return json.loads(output)
            except json.JSONDecodeError:
                pass
        return None
