"""License text verification against upstream package archives.

Fetches the published package archive for a component, extracts shipped
license files, parses them with the existing text heuristics and compares
the result to the declared license. Flag-only: the declared license is
never rewritten here — mismatches are reported as data.

Statuses (stored on each ``licenses.json`` entry as ``verification``):

  verified         shipped license text matches the declared license
  mismatch         shipped text parsed to a different known license
  no_license_text  archive ships no recognizable license text
  unavailable      registry unreachable / artifact missing / fetch failed
  not_applicable   unsupported ecosystem or missing version (visible, never silent)
"""

from __future__ import annotations

import io
import json
import logging
import re
import tarfile
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from hashlib import md5
from urllib.parse import quote, unquote

from ..sbom.purl import purl_identity
from ..utils.cache import get_cache
from ..utils.rate_limiter import RetryClient, rate_limit_request
from .text_parser import LICENSE_FILE_PATTERNS, MAX_LICENSE_FILE_SIZE, LicenseTextParser

logger = logging.getLogger("sbom.license.verify")

VERIFIED = "verified"
MISMATCH = "mismatch"
NO_LICENSE_TEXT = "no_license_text"
UNAVAILABLE = "unavailable"
NOT_APPLICABLE = "not_applicable"

CACHE_PREFIX = "licverify:"
HTTP_TIMEOUT = 30.0
MAX_ARCHIVE_BYTES = 30 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 20_000
MAX_NESTING_DEPTH = 2
MAX_LICENSE_CANDIDATES = 16
VERIFY_WORKERS = 4

# Exact member names plus prefix variants (LICENSE-APACHE-2.0, copying.gpl, ...).
_LICENSE_BASENAMES = frozenset(p.lower() for p in LICENSE_FILE_PATTERNS)
_LICENSE_BASE_RE = re.compile(r"^(?:licen[cs]e|copying)(?:[-_.].*)?$")
_NESTED_SUFFIXES = (".tar.gz", ".tgz", ".tar")
_GITHUB_ZIPBALL_RE = re.compile(
    r"^https://api\.github\.com/repos/([^/]+/[^/]+)/zipball/(.+)$"
)
_GITHUB_GIT_RE = re.compile(r"^https://github\.com/([^/]+/[^/]+?)(?:\.git)?$")


class _NotApplicable:
    """Provider sentinel: this purl cannot be fetched by design."""


NA = _NotApplicable()


@dataclass(frozen=True)
class _Parts:
    ptype: str
    namespace: str
    name: str
    version: str
    qualifiers: dict


_client: RetryClient | None = None
_client_lock = threading.Lock()
_parser = LicenseTextParser()


def _http() -> RetryClient:
    global _client
    if _client is None:
        with _client_lock:
            if _client is None:
                _client = RetryClient(timeout=HTTP_TIMEOUT)
    return _client


def _fetch(url: str) -> bytes | None:
    domain = url.split("/")[2] if url.startswith(("http://", "https://")) else ""
    resp = None
    for attempt in range(3):
        try:
            if domain:
                rate_limit_request(domain)
        except Exception:  # noqa: BLE001, S110 - rate limiting must never block verification
            pass
        resp = _http().get(url)
        if resp is None or resp.status_code not in (408, 429):
            break
        time.sleep(1.5 * (attempt + 1))
    if resp is None or resp.status_code != 200:
        return None
    data = resp.content
    if len(data) > MAX_ARCHIVE_BYTES:
        logger.debug("Archive too large, skipping: %s (%d bytes)", url, len(data))
        return None
    return data


def _fetch_json(url: str) -> dict | None:
    data = _fetch(url)
    if data is None:
        return None
    try:
        parsed = json.loads(data.decode("utf-8", errors="replace"))
    except (ValueError, UnicodeDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _qualifiers(purl: str) -> dict:
    _, _, qs = str(purl or "").partition("?")
    out: dict = {}
    for part in qs.split("&"):
        if not part:
            continue
        k, _, v = part.partition("=")
        if k:
            out[unquote(k)] = unquote(v)
    return out


# ---------------------------------------------------------------- providers


def _prov_npm(p: _Parts) -> bytes | None:
    full = f"{p.namespace}/{p.name}" if p.namespace else p.name
    return _fetch(
        f"https://registry.npmjs.org/{full}/-/{p.name}-{p.version}.tgz"
    )


def _prov_maven(p: _Parts):
    if p.qualifiers.get("type") not in (None, "", "jar"):
        return NA
    if not p.namespace:
        return NA
    path = f"{p.namespace.replace('.', '/')}/{p.name}/{p.version}/{p.name}-{p.version}.jar"
    for base in (
        "https://repo1.maven.org/maven2",
        # Google-hosted Central mirror: survives Central's IP rate limits.
        "https://maven-central.storage-download.googleapis.com/maven2",
        "https://repo.clojars.org",
    ):
        data = _fetch(f"{base}/{path}")
        if data:
            return data
    return None


def _prov_pypi(p: _Parts) -> bytes | None:
    meta = _fetch_json(
        f"https://pypi.org/pypi/{quote(p.name)}/{quote(p.version)}/json"
    )
    if not meta:
        return None
    urls = meta.get("urls") or []
    wheel = next(
        (u for u in urls if isinstance(u, dict) and u.get("packagetype") == "bdist_wheel"),
        None,
    )
    sdist = next(
        (u for u in urls if isinstance(u, dict) and u.get("packagetype") == "sdist"),
        None,
    )
    target = wheel or sdist
    if not target or not target.get("url"):
        return None
    return _fetch(str(target["url"]))


def _prov_golang(p: _Parts):
    module = f"{p.namespace}/{p.name}" if p.namespace else p.name
    escaped = re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), module)
    candidates = []
    if p.version.startswith("v"):
        candidates.append(p.version)
    else:
        candidates.extend((p.version, f"v{p.version}"))
    for ver in candidates:
        data = _fetch(
            f"https://proxy.golang.org/{escaped}/@v/{quote(ver, safe='')}.zip"
        )
        if data:
            return data
    vcs = p.qualifiers.get("vcs_url") or ""
    gh = _GITHUB_GIT_RE.match(vcs.rstrip("/"))
    if gh and p.version:
        data = _fetch(
            f"https://codeload.github.com/{gh.group(1)}/tar.gz/{quote(p.version, safe='')}"
        )
        if data:
            return data
    return None


def _prov_cargo(p: _Parts) -> bytes | None:
    return _fetch(
        f"https://static.crates.io/crates/{p.name}/{p.name}-{p.version}.crate"
    )


def _prov_nuget(p: _Parts) -> bytes | None:
    name = p.name.lower()
    ver = p.version.lower()
    return _fetch(
        f"https://api.nuget.org/v3-flatcontainer/{name}/{ver}/{name}.{ver}.nupkg"
    )


def _prov_gem(p: _Parts) -> bytes | None:
    return _fetch(f"https://rubygems.org/gems/{p.name}-{p.version}.gem")


def _prov_pub(p: _Parts) -> bytes | None:
    return _fetch(
        f"https://pub.dev/api/archives/{quote(p.name)}-{quote(p.version)}.tar.gz"
    )


def _prov_hex(p: _Parts) -> bytes | None:
    return _fetch(f"https://repo.hex.pm/tarballs/{p.name}-{p.version}.tar")


def _prov_hackage(p: _Parts) -> bytes | None:
    ident = f"{p.name}-{p.version}"
    return _fetch(
        f"https://hackage.haskell.org/package/{ident}/{ident}.tar.gz"
    )


def _prov_cran(p: _Parts) -> bytes | None:
    data = _fetch(
        f"https://cran.r-project.org/src/contrib/{p.name}_{p.version}.tar.gz"
    )
    if data:
        return data
    return _fetch(
        f"https://cran.r-project.org/src/contrib/Archive/{p.name}/{p.name}_{p.version}.tar.gz"
    )


def _prov_cpan(p: _Parts) -> bytes | None:
    info = _fetch_json(
        f"https://fastapi.metacpan.org/v1/download_url/{quote(p.name)}"
    )
    if not info:
        return None
    info_version = str(info.get("version") or "")
    if p.version and info_version and info_version != p.version:
        # Latest release only; a different version cannot be addressed.
        return None
    url = info.get("download_url")
    if not url:
        return None
    return _fetch(str(url))


def _prov_composer(p: _Parts) -> bytes | None:
    if not p.namespace:
        return NA
    package = f"{p.namespace}/{p.name}"
    meta = _fetch_json(f"https://repo.packagist.org/p2/{package}.json")
    if not meta:
        return None
    releases = (meta.get("packages") or {}).get(package) or []
    wanted = p.version.lstrip("v")
    chosen = None
    for rel in releases:
        if not isinstance(rel, dict):
            continue
        ver = str(rel.get("version") or "")
        norm = str(rel.get("version_normalized") or "")
        if ver.lstrip("v") == wanted or norm.startswith(wanted):
            chosen = rel
            break
    if chosen is None:
        return None
    dist = chosen.get("dist") or {}
    url = str(dist.get("url") or "")
    m = _GITHUB_ZIPBALL_RE.match(url)
    if m:
        url = f"https://codeload.github.com/{m.group(1)}/tar.gz/{m.group(2)}"
    if not url:
        source = chosen.get("source") or {}
        git = str(source.get("git") or source.get("url") or "")
        ref = dist.get("reference") or source.get("reference")
        gh = _GITHUB_GIT_RE.match(git.rstrip("/"))
        if gh and ref:
            url = f"https://codeload.github.com/{gh.group(1)}/tar.gz/{quote(str(ref), safe='')}"
    if not url:
        return None
    return _fetch(url)


def _prov_swift(p: _Parts):
    path = f"{p.namespace}/{p.name}" if p.namespace else p.name
    if "/" not in path:
        # Bare package name — repository host unknown (purl spec has none).
        return NA
    parts = path.split("/")
    if len(parts) < 3 or parts[0] != "github.com" or not p.version:
        return NA
    owner, repo = parts[1], parts[2].removesuffix(".git")
    return _fetch(
        f"https://codeload.github.com/{owner}/{repo}/tar.gz/{quote(p.version, safe='')}"
    )


def _prov_cocoapods(p: _Parts) -> bytes | None:
    digest = md5(p.name.encode("utf-8")).hexdigest()
    spec_url = (
        f"https://cdn.cocoapods.org/Specs/{digest[0]}/{digest[1]}/{digest[2]}"
        f"/{quote(p.name)}/{quote(p.version)}.json"
    )
    spec = _fetch_json(spec_url)
    if not spec:
        return None
    source = spec.get("source") or {}
    git = str(source.get("git") or "")
    ref = source.get("tag") or source.get("commit") or p.version
    gh = _GITHUB_GIT_RE.match(git.rstrip("/"))
    if not gh:
        return None
    return _fetch(
        f"https://codeload.github.com/{gh.group(1)}/tar.gz/{quote(str(ref), safe='')}"
    )


def _prov_generic(p: _Parts):
    if p.qualifiers.get("type") != "elm" or not p.namespace or not p.version:
        return NA
    return _fetch(
        f"https://codeload.github.com/{p.namespace}/{p.name}"
        f"/tar.gz/{quote(p.version, safe='')}"
    )


_PROVIDERS = {
    "npm": _prov_npm,
    "maven": _prov_maven,
    "pypi": _prov_pypi,
    "golang": _prov_golang,
    "cargo": _prov_cargo,
    "nuget": _prov_nuget,
    "gem": _prov_gem,
    "pub": _prov_pub,
    "hex": _prov_hex,
    "hackage": _prov_hackage,
    "cran": _prov_cran,
    "cpan": _prov_cpan,
    "composer": _prov_composer,
    "swift": _prov_swift,
    "cocoapods": _prov_cocoapods,
    "generic": _prov_generic,
}


# ------------------------------------------------------------ extraction


def _is_safe_member(name: str) -> bool:
    if not name:
        return False
    norm = name.replace("\\", "/")
    if norm.startswith("/") or re.match(r"^[A-Za-z]:", norm):
        return False
    return ".." not in norm.split("/")


def _is_license_name(member: str) -> bool:
    base = member.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if base in _LICENSE_BASENAMES:
        return True
    return bool(_LICENSE_BASE_RE.match(base))


def _is_nested(member: str) -> bool:
    return member.replace("\\", "/").lower().endswith(_NESTED_SUFFIXES)


def _add_candidate(
    candidates: list, member: str, blob: bytes, parser: LicenseTextParser
) -> None:
    text = blob.decode("utf-8", errors="ignore")
    for spdx_id, score in parser.match_license_candidates(text):
        candidates.append(
            {"file": member, "spdx_id": spdx_id, "score": score,
             "confidence": parser.get_confidence(spdx_id, score)}
        )


def _walk_zip(data: bytes, depth: int, candidates: list, parser: LicenseTextParser) -> None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError):
        return
    with zf:
        seen = 0
        for info in zf.infolist():
            seen += 1
            if seen > MAX_ARCHIVE_MEMBERS or len(candidates) >= MAX_LICENSE_CANDIDATES:
                return
            if info.is_dir() or not _is_safe_member(info.filename):
                continue
            if _is_license_name(info.filename):
                if info.file_size > MAX_LICENSE_FILE_SIZE:
                    continue
                try:
                    blob = zf.read(info)
                except (zipfile.BadZipFile, OSError, RuntimeError):
                    continue
                _add_candidate(candidates, info.filename, blob, parser)
            elif depth < MAX_NESTING_DEPTH and _is_nested(info.filename):
                if info.file_size > MAX_ARCHIVE_BYTES:
                    continue
                try:
                    blob = zf.read(info)
                except (zipfile.BadZipFile, OSError, RuntimeError):
                    continue
                _walk_blob(blob, depth + 1, candidates, parser)


def _walk_tar(data: bytes, depth: int, candidates: list, parser: LicenseTextParser) -> None:
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")  # noqa: SIM115
    except (tarfile.TarError, OSError, EOFError):
        return
    with tf:
        seen = 0
        for member in tf:
            seen += 1
            if seen > MAX_ARCHIVE_MEMBERS or len(candidates) >= MAX_LICENSE_CANDIDATES:
                return
            if not member.isfile() or not _is_safe_member(member.name):
                continue
            if _is_license_name(member.name):
                if member.size > MAX_LICENSE_FILE_SIZE:
                    continue
                try:
                    fh = tf.extractfile(member)
                    blob = fh.read() if fh else b""
                except (tarfile.TarError, OSError, EOFError):
                    continue
                _add_candidate(candidates, member.name, blob, parser)
            elif depth < MAX_NESTING_DEPTH and _is_nested(member.name):
                if member.size > MAX_ARCHIVE_BYTES:
                    continue
                try:
                    fh = tf.extractfile(member)
                    blob = fh.read() if fh else b""
                except (tarfile.TarError, OSError, EOFError):
                    continue
                _walk_blob(blob, depth + 1, candidates, parser)


def _walk_blob(data: bytes, depth: int, candidates: list, parser: LicenseTextParser) -> None:
    if not data or depth > MAX_NESTING_DEPTH or len(candidates) >= MAX_LICENSE_CANDIDATES:
        return
    if data[:4] == b"PK\x03\x04":
        _walk_zip(data, depth, candidates, parser)
    else:
        _walk_tar(data, depth, candidates, parser)


# ------------------------------------------------------------ comparison


def _declared_tokens(declared: str | None) -> set[str]:
    """Lower-cased acceptable ids for an SPDX expression / id / junk value."""
    text = str(declared or "").strip()
    if not text:
        return set()
    tokens = {text.lower()}
    for piece in re.split(r"\s+(?:OR|AND)\s+", text, flags=re.IGNORECASE):
        piece = piece.strip().strip("()")
        if piece:
            tokens.add(piece.lower())
            base = re.split(r"\s+WITH\s+", piece, flags=re.IGNORECASE)[0].strip()
            if base:
                tokens.add(base.lower())
    return tokens


def _result(status: str, spdx_id: str = "", confidence: float = 0.0,
            file: str = "") -> dict:
    return {
        "verification": status,
        "text_spdx_id": spdx_id,
        "text_confidence": confidence,
        "text_file": file,
    }


def _evaluate(data: bytes, declared: str | None) -> dict:
    candidates: list[dict] = []
    _walk_blob(data, 0, candidates, _parser)
    if not candidates:
        return _result(NO_LICENSE_TEXT)
    tokens = _declared_tokens(declared)
    hits = [c for c in candidates if c["spdx_id"].lower() in tokens]
    if hits:
        best = max(hits, key=lambda c: (c["score"], c["confidence"]))
        return _result(
            VERIFIED, best["spdx_id"], best["confidence"], best["file"]
        )
    best = max(candidates, key=lambda c: (c["score"], c["confidence"]))
    return _result(
        MISMATCH, best["spdx_id"], best["confidence"], best["file"]
    )


def verify_license_text(purl: str, declared: str | None = None) -> dict:
    """Verify one component's declared license against its package archive.

    Always returns the full result dict; cached per ``(purl, declared)``.
    """
    purl = str(purl or "")
    if not purl:
        return _result(NOT_APPLICABLE)
    ptype, namespace, name, version = purl_identity(purl)
    if not ptype or not name or not version:
        return _result(NOT_APPLICABLE)
    provider = _PROVIDERS.get(ptype)
    if provider is None:
        return _result(NOT_APPLICABLE)

    cache = get_cache()
    cache_key = f"{CACHE_PREFIX}{purl}|{declared or ''}"
    cached = cache.get(cache_key)
    if isinstance(cached, dict) and cached.get("verification"):
        return dict(cached)

    parts = _Parts(
        ptype=ptype,
        namespace=namespace,
        name=name,
        version=version,
        qualifiers=_qualifiers(purl),
    )
    try:
        data = provider(parts)
    except Exception as e:  # noqa: BLE001 - one bad provider must not fail the stage
        logger.debug("Provider %s failed for %s: %s", ptype, purl, e)
        data = None

    if data is NA:
        result = _result(NOT_APPLICABLE)
    elif not data:
        result = _result(UNAVAILABLE)
    else:
        result = _evaluate(bytes(data), declared)

    # Transient failures must stay retryable on the next run/scan.
    if result["verification"] != UNAVAILABLE:
        try:
            cache.set(cache_key, result)
        except Exception:  # noqa: BLE001, S110 - cache problems must not fail verification
            pass
    return result


def verify_many(entries: list[dict], max_workers: int = VERIFY_WORKERS) -> None:
    """Run ``verify_license_text`` for every licenses.json entry in place."""
    if not entries:
        return
    workers = max(1, min(max_workers, len(entries)))

    def _one(entry: dict) -> None:
        try:
            result = verify_license_text(
                str(entry.get("purl") or ""), str(entry.get("spdx_id") or "")
            )
            entry.update(result)
        except Exception as e:  # noqa: BLE001 - never fail the graph node
            logger.warning(
                "License verification failed for %s: %s", entry.get("name"), e
            )
            entry["verification"] = UNAVAILABLE

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(_one, entries))
