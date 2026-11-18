"""Registry producer/supplier enrichment for components with no producer record.

Candidates are gathered from three standardized sources queried together — the
ecosystem's primary registry, packages.ecosyste.ms and CodeMeta 3.0 — then
deduplicated into producer entities (matched by email and normalized name) and
ranked:

1. the curated offline map (``config/producers.json``): public-record
   producers, always wins;
2. organization tier: declared organization fields (Maven POM
   ``<organization>``, CodeMeta Organization), the linked repository's
   organization owner, then a guarded namespace/scope brand;
3. person tier: display names (repository owner, registry author, CodeMeta
   person, packages.ecosyste.ms maintainer);
4. login tier: usernames only when no display name exists anywhere.

Every result carries provenance in ``evidence.supplier`` (name, sources,
alternatives, method). Failures degrade to "missing" — nothing is ever
invented.
"""

from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote
from xml.etree import ElementTree

from ..utils.cache import get_cache
from ..utils.rate_limiter import RetryClient, rate_limit_request

logger = logging.getLogger("sbom.collectors.producer")

_CONFIG_DIR = Path(__file__).resolve().parent.parent.parent / "config"


def _load_json_config(filename: str) -> dict:
    config_path = _CONFIG_DIR / filename
    if config_path.exists():
        try:
            with open(config_path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}
    return {}


# Curated purl-prefix → producer map (config/producers.json): public-record
# producer facts for artifacts whose registry metadata is unavailable. Only
# consulted for components that carry no producer record at all.
CURATED_PRODUCERS: dict = _load_json_config("producers.json")

NPM_REGISTRY_BASE = "https://registry.npmjs.org"
ECOSYSTE_MS_BASE = "https://packages.ecosyste.ms/api/v1/registries"
PYPI_BASE = "https://pypi.org"
MAVEN_CENTRAL_BASE = "https://repo1.maven.org/maven2"
CRATES_BASE = "https://crates.io/api/v1/crates"
RUBYGEMS_BASE = "https://rubygems.org/api/v1/gems"
PACKAGIST_BASE = "https://repo.packagist.org/p2"
NUGET_REG_BASE = "https://api.nuget.org/v3/registration5-semver1"

_SUPPLIER_KEYS = ("supplier", "origin", "maintainer")
_USER_AGENT = "sbom-generator/1.0"
_MAX_AUTHOR_LEN = 100
_CACHE_MAX_BYTES = 1_000_000
_ENRICH_WORKERS = 6

# packages.ecosyste.ms registry hosts, keyed by component ecosystem. Every
# host was verified live against the registry catalog before being listed;
# ecosystems without a genuine source stay honest "missing".
_ECOSYSTEM_REGISTRIES: dict[str, str] = {
    "npm": "npmjs.org",
    "pypi": "pypi.org",
    "maven": "repo1.maven.org",
    "gradle": "repo1.maven.org",
    "sbt": "repo1.maven.org",
    "golang": "proxy.golang.org",
    "nuget": "nuget.org",
    "cargo": "crates.io",
    "ruby": "rubygems.org",
    "composer": "packagist.org",
    "dart": "pub.dev",
    "hex": "hex.pm",
    "r": "cran.r-project.org",
    "perl": "metacpan.org",
    "elm": "package.elm-lang.org",
    "haskell": "hackage.haskell.org",
    "swift": "swiftpackageindex.com",
    "terraform": "registry.terraform.io",
    "docker": "hub.docker.com",
    "julia": "juliahub.com",
    "deno": "deno.land",
    "clojure": "clojars.org",
    "conan": "conan.io",
    "vcpkg": "vcpkg.io",
}

_ENRICHABLE_ECOSYSTEMS = frozenset(_ECOSYSTEM_REGISTRIES)

# Registry package-key shapes on packages.ecosyste.ms (verified live).
_COLON_KEY_ECOS = frozenset({"maven", "gradle", "sbt"})
_NAME_KEY_ECOS = frozenset({
    "pypi", "cargo", "ruby", "nuget", "dart", "r", "perl",
    "julia", "haskell", "conan", "vcpkg", "hex",
})

# Candidate ranking: lower wins. Organizations outrank people, and inside a
# tier the declared/authoritative source beats the derived one.
_RANK_TYPED_ORG = 0
_RANK_OWNER_ORG = 1
_RANK_BRAND_ORG = 2
_RANK_OWNER_PERSON = 3
_RANK_REGISTRY_PERSON = 4
_RANK_CODEMETA_PERSON = 5
_RANK_ECOSYSTE_MS_PERSON = 6

_NON_BRAND_NAMESPACES = frozenset({"library", "official", "hexpm", "unknown"})
_BRAND_GROUP_ECOS = frozenset({"npm", "docker", "terraform", "deno"})


def _needs_producer(component: dict) -> bool:
    """True when the component is enrichable and carries no producer record."""
    if component.get("ecosystem") not in _ENRICHABLE_ECOSYSTEMS:
        return False
    if not str(component.get("name") or ""):
        return False
    if any(component.get(key) for key in _SUPPLIER_KEYS):
        return False
    evidence = component.get("evidence") or {}
    return not evidence.get("supplier")


@dataclass(frozen=True)
class Candidate:
    """One producer claim from one source, before deduplication."""

    name: str
    kind: str       # "org" | "person"
    rank: int
    source: str     # e.g. "registry:npm", "ecosyste.ms:owner", "codemeta"
    form: str = "display"   # "display" | "login"
    email: str = ""


@dataclass(eq=False)
class _Entity:
    """Deduplicated producer entity (one candidate identity)."""

    name: str
    kind: str
    form: str
    rank: int
    email: str
    sources: list[str]


def _clean_name(value) -> str | None:
    """A plausible display name from an author-ish registry value."""
    if isinstance(value, dict):
        value = value.get("name")
    if not isinstance(value, str):
        return None
    # "Name <email>" / "Name (url)" — keep the leading name only.
    for sep in ("<", "("):
        if sep in value:
            value = value.split(sep, 1)[0]
    value = " ".join(value.split()).strip(" ,;")
    if not value or len(value) > _MAX_AUTHOR_LEN:
        return None
    if "@" in value and " " not in value:      # bare email
        return None
    if value.startswith(("http://", "https://", "www.")):
        return None
    if value.lower() in ("null", "none", "n/a", "undefined"):
        return None
    return value


def _email_of(value) -> str:
    if isinstance(value, dict):
        value = value.get("email")
    if not isinstance(value, str):
        return ""
    value = value.strip().lower()
    return value if "@" in value and " " not in value else ""


def _split_name_email(raw) -> tuple[str | None, str]:
    """Display name and email from ``Name <email>``-style registry values."""
    if isinstance(raw, dict):
        return _clean_name(raw), _email_of(raw.get("email"))
    if not isinstance(raw, str):
        return None, ""
    email = ""
    if "<" in raw and ">" in raw:
        inner = raw.split("<", 1)[1].split(">", 1)[0].strip().lower()
        if "@" in inner:
            email = inner
    return _clean_name(raw), email


def _form_of(name: str) -> str:
    """Display name (words / capitalised) vs plain username."""
    return "display" if (" " in name or name[:1].isupper()) else "login"


def _norm_key(text: str) -> str:
    return "".join(ch for ch in text.lower() if ch.isalnum())


def _person(name: str, rank: int, source: str, email: str = "") -> Candidate:
    return Candidate(name=name, kind="person", rank=rank, source=source,
                     form=_form_of(name), email=email)


def _maintainers_of(doc: dict) -> list[dict]:
    maintainers = doc.get("maintainers") or []
    if isinstance(maintainers, dict):
        maintainers = [maintainers]
    return [m for m in maintainers if isinstance(m, dict)]


def _request(client: RetryClient, url: str, domain: str):
    """Rate-limited GET that never raises — enrichment must not break a scan."""
    rate_limit_request(domain)
    headers = {"Accept": "application/json", "User-Agent": _USER_AGENT}
    try:
        return client.get(url, headers=headers)
    except Exception as e:  # noqa: BLE001 - enrichment is best-effort
        logger.debug("producer lookup failed for %s: %s", url, e)
        return None


def _fetch_json(client: RetryClient, url: str, domain: str) -> dict | None:
    cache = get_cache()
    cached = cache.get(url)
    if isinstance(cached, dict) and "status" in cached:
        value = cached.get("value")
        return value if cached["status"] == 200 and isinstance(value, dict) else None
    resp = _request(client, url, domain)
    if resp is None or resp.status_code != 200:
        status = resp.status_code if resp is not None else None
        if resp is not None and resp.status_code == 404:
            cache.set(url, {"status": 404})
        logger.debug("producer lookup status=%s for %s", status, url)
        return None
    try:
        data = resp.json()
    except Exception as e:  # noqa: BLE001
        logger.debug("producer lookup parse failed for %s: %s", url, e)
        return None
    if not isinstance(data, dict):
        return None
    if len(resp.content) <= _CACHE_MAX_BYTES:
        cache.set(url, {"status": 200, "value": data})
    return data


def _fetch_text(client: RetryClient, url: str, domain: str) -> str | None:
    cache = get_cache()
    cached = cache.get(url)
    if isinstance(cached, dict) and "status" in cached:
        value = cached.get("value")
        return value if cached["status"] == 200 and isinstance(value, str) else None
    resp = _request(client, url, domain)
    if resp is None or resp.status_code != 200:
        status = resp.status_code if resp is not None else None
        if resp is not None and resp.status_code == 404:
            cache.set(url, {"status": 404})
        logger.debug("producer lookup status=%s for %s", status, url)
        return None
    text = resp.text
    if not text:
        return None
    if len(resp.content) <= _CACHE_MAX_BYTES:
        cache.set(url, {"status": 200, "value": text})
    return text


def _registry_package_name(component: dict) -> str:
    """Package name the way the ecosystem's registry spells it."""
    eco = component.get("ecosystem") or ""
    name = str(component.get("name") or "")
    group = str(component.get("group") or "")
    if not name:
        return ""
    if eco in _COLON_KEY_ECOS:
        return f"{group}:{name}" if group else name
    if eco in _NAME_KEY_ECOS:
        return name
    if group:
        if "/" in name:
            return name
        return f"{group}/{name}"
    return name


def _fetch_npm_doc(client: RetryClient, package_name: str) -> dict | None:
    if not package_name:
        return None
    return _fetch_json(
        client, f"{NPM_REGISTRY_BASE}/{quote(package_name, safe='')}",
        "registry.npmjs.org",
    )


def _fetch_npm_candidates(client: RetryClient, component: dict) -> list[Candidate]:
    doc = _fetch_npm_doc(client, _registry_package_name(component))
    if not doc:
        return []
    out: list[Candidate] = []
    author = doc.get("author")
    if isinstance(author, list):
        author = author[0] if author else None
    name, email = _split_name_email(author)
    if name:
        out.append(_person(name, _RANK_REGISTRY_PERSON, "registry:npm", email))
    for maintainer in _maintainers_of(doc):
        raw = maintainer.get("name") or maintainer.get("login")
        if isinstance(raw, str) and raw.strip():
            out.append(_person(raw.strip(), _RANK_REGISTRY_PERSON, "registry:npm",
                               _email_of(maintainer.get("email"))))
    return out


def _fetch_pypi_candidates(client: RetryClient, component: dict) -> list[Candidate]:
    name = str(component.get("name") or "")
    if not name:
        return []
    data = _fetch_json(client, f"{PYPI_BASE}/pypi/{quote(name, safe='')}/json",
                       "pypi.org")
    info = data.get("info") if isinstance(data, dict) else None
    if not isinstance(info, dict):
        return []
    out: list[Candidate] = []
    author_name, author_email = _split_name_email(info.get("author"))
    if not author_email:
        author_email = _email_of(info.get("author_email"))
    if author_name:
        out.append(_person(author_name, _RANK_REGISTRY_PERSON, "registry:pypi",
                           author_email))
    elif author_email:
        out.append(Candidate(name="", kind="person", rank=_RANK_REGISTRY_PERSON,
                             source="registry:pypi", email=author_email))
    maintainer_name, maintainer_email = _split_name_email(info.get("maintainer"))
    if maintainer_name:
        out.append(_person(maintainer_name, _RANK_REGISTRY_PERSON, "registry:pypi",
                           maintainer_email or _email_of(info.get("maintainer_email"))))
    return out


def _parse_pom_candidates(pom_text: str, source: str) -> list[Candidate]:
    try:
        root = ElementTree.fromstring(pom_text)
    except ElementTree.ParseError:
        return []
    out: list[Candidate] = []
    org = root.find("./{*}organization/{*}name")
    if org is not None:
        found = _clean_name(org.text)
        if found:
            out.append(Candidate(name=found, kind="org", rank=_RANK_TYPED_ORG,
                                 source=source, form="display"))
    for node in root.findall("./{*}developers/{*}developer/{*}name"):
        found = _clean_name(node.text)
        if found:
            out.append(_person(found, _RANK_REGISTRY_PERSON, source))
    return out


def _fetch_maven_candidates(client: RetryClient, component: dict) -> list[Candidate]:
    group = str(component.get("group") or "")
    name = str(component.get("name") or "")
    version = str(component.get("version") or "")
    if not (group and name and version):
        return []
    path = f"{group.replace('.', '/')}/{name}/{version}/{name}-{version}.pom"
    text = _fetch_text(client, f"{MAVEN_CENTRAL_BASE}/{path}", "repo1.maven.org")
    if not text:
        return []
    return _parse_pom_candidates(text, "registry:maven")


def _fetch_cargo_candidates(client: RetryClient, component: dict) -> list[Candidate]:
    name = str(component.get("name") or "")
    if not name:
        return []
    data = _fetch_json(client, f"{CRATES_BASE}/{quote(name, safe='')}", "crates.io")
    if not data:
        return []
    versions = data.get("versions")
    if not isinstance(versions, list):
        return []
    target = str(component.get("version") or "")
    candidates = [v for v in versions
                  if isinstance(v, dict) and target and v.get("num") == target]
    candidates += [v for v in versions
                   if isinstance(v, dict) and v not in candidates]
    for version in candidates:
        found = _clean_name(version.get("published_by"))
        if found:
            return [_person(found, _RANK_REGISTRY_PERSON, "registry:crates.io")]
    return []


def _fetch_rubygems_candidates(client: RetryClient, component: dict) -> list[Candidate]:
    name = str(component.get("name") or "")
    if not name:
        return []
    data = _fetch_json(client, f"{RUBYGEMS_BASE}/{quote(name, safe='')}.json",
                       "rubygems.org")
    if not data:
        return []
    out: list[Candidate] = []
    authors = data.get("authors")
    entries = authors if isinstance(authors, list) else [authors]
    for entry in entries:
        found = _clean_name(entry) if not isinstance(entry, str) else (
            _clean_name(entry.split(",")[0]))
        if found:
            out.append(_person(found, _RANK_REGISTRY_PERSON, "registry:rubygems.org"))
    return out


def _fetch_packagist_candidates(client: RetryClient, component: dict) -> list[Candidate]:
    group = str(component.get("group") or "")
    name = str(component.get("name") or "")
    package = f"{group}/{name}" if group and "/" not in name else name
    if not package or "/" not in package:
        return []
    data = _fetch_json(client, f"{PACKAGIST_BASE}/{quote(package, safe='/')}.json",
                       "repo.packagist.org")
    if not data:
        return []
    packages = data.get("packages")
    entries = packages.get(package) if isinstance(packages, dict) else None
    out: list[Candidate] = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        authors = entry.get("authors") or []
        if isinstance(authors, dict):
            authors = [authors]
        for author in authors:
            name_found, email = _split_name_email(
                author.get("name") if isinstance(author, dict) else author
            )
            if name_found:
                out.append(_person(name_found, _RANK_REGISTRY_PERSON,
                                   "registry:packagist.org",
                                   email or (_email_of(author.get("email"))
                                             if isinstance(author, dict) else "")))
    return out


def _fetch_nuget_candidates(client: RetryClient, component: dict) -> list[Candidate]:
    """Declared authors of a NuGet package (registration API)."""
    name = str(component.get("name") or "").strip()
    if not name:
        return []
    url = f"{NUGET_REG_BASE}/{quote(name.lower(), safe='')}/index.json"
    data = _fetch_json(client, url, "api.nuget.org")
    if not data:
        return []
    out: list[Candidate] = []
    for page in data.get("items") or []:
        if not isinstance(page, dict):
            continue
        entries = page.get("items")
        if not isinstance(entries, list) and page.get("@id"):
            page_doc = _fetch_json(client, str(page["@id"]), "api.nuget.org")
            entries = page_doc.get("items") if isinstance(page_doc, dict) else None
        for item in entries or []:
            if not isinstance(item, dict):
                continue
            entry = item.get("catalogEntry")
            if not isinstance(entry, dict):
                continue
            authors = entry.get("authors")
            if isinstance(authors, str):
                authors = [authors]
            for author in authors or []:
                found, email = _split_name_email(author)
                if found:
                    out.append(_person(found, _RANK_REGISTRY_PERSON,
                                       "registry:nuget.org", email))
        if out:
            break
    return out


# Primary registry fetchers keyed by ecosystem; every ecosystem also queries
# packages.ecosyste.ms and CodeMeta — these only add declared fields.
_PRIMARY_FETCHERS = {
    "npm": _fetch_npm_candidates,
    "pypi": _fetch_pypi_candidates,
    "maven": _fetch_maven_candidates,
    "gradle": _fetch_maven_candidates,
    "sbt": _fetch_maven_candidates,
    "cargo": _fetch_cargo_candidates,
    "ruby": _fetch_rubygems_candidates,
    "composer": _fetch_packagist_candidates,
    "nuget": _fetch_nuget_candidates,
}


def _registry_candidates(client: RetryClient, component: dict) -> list[Candidate]:
    fetcher = _PRIMARY_FETCHERS.get(component.get("ecosystem") or "")
    if fetcher is None:
        return []
    try:
        return fetcher(client, component) or []
    except Exception as e:  # noqa: BLE001 - enrichment must never break a scan
        logger.debug("registry producer lookup failed for %s: %s",
                     component.get("name"), e)
        return []


def _fetch_ecosyste_ms_package(client: RetryClient, component: dict) -> dict | None:
    eco = component.get("ecosystem") or ""
    registry = _ECOSYSTEM_REGISTRIES.get(eco)
    package = _registry_package_name(component)
    if not registry or not package:
        return None
    url = (f"{ECOSYSTE_MS_BASE}/{registry}/packages/"
           f"{quote(package, safe='/:@')}")
    return _fetch_json(client, url, "packages.ecosyste.ms")


def _resolve_owner_record(client: RetryClient, data: dict) -> dict:
    repo = data.get("repo_metadata") if isinstance(data.get("repo_metadata"), dict) else {}
    owner = repo.get("owner_record")
    if isinstance(owner, dict) and owner.get("kind"):
        return owner
    owner_url = repo.get("owner_url")
    if isinstance(owner_url, str) and owner_url.startswith("http"):
        backfilled = _fetch_json(client, owner_url, "repos.ecosyste.ms")
        if isinstance(backfilled, dict) and backfilled.get("kind"):
            return backfilled
    return owner if isinstance(owner, dict) else {}


def _ecosyste_ms_candidates(client: RetryClient, component: dict,
                            data: dict | None) -> tuple[list[Candidate], str]:
    """Owner and maintainer candidates from packages.ecosyste.ms.

    Returns the candidates plus the repository owner's login (the oracle for
    the namespace/scope brand guard).
    """
    if not isinstance(data, dict):
        return [], ""
    out: list[Candidate] = []
    owner = _resolve_owner_record(client, data)
    owner_login = str(owner.get("login") or "")
    if not owner_login:
        repo = data.get("repo_metadata")
        if isinstance(repo, dict) and isinstance(repo.get("owner"), str):
            owner_login = repo["owner"]
    email = _email_of(owner.get("email"))
    if owner.get("kind") == "organization":
        name = _clean_name(owner.get("name")) or _clean_name(owner.get("login"))
        if name:
            out.append(Candidate(name=name, kind="org", rank=_RANK_OWNER_ORG,
                                 source="ecosyste.ms:owner", form="display",
                                 email=email))
    elif owner.get("kind"):
        name = _clean_name(owner.get("name"))
        if name:
            out.append(_person(name, _RANK_OWNER_PERSON, "ecosyste.ms:owner", email))
        elif owner_login:
            out.append(Candidate(name=owner_login, kind="person",
                                 rank=_RANK_OWNER_PERSON,
                                 source="ecosyste.ms:owner", form="login",
                                 email=email))
    for maintainer in _maintainers_of(data):
        raw = maintainer.get("name") or maintainer.get("login")
        if isinstance(raw, str) and raw.strip():
            out.append(_person(raw.strip(), _RANK_ECOSYSTE_MS_PERSON,
                               "ecosyste.ms:maintainer",
                               _email_of(maintainer.get("email"))))
    return out, owner_login


def _brand_candidates(component: dict, data: dict | None,
                      owner_login: str) -> list[Candidate]:
    """Guarded namespace/scope brand: accepted only when it is not the
    repository owner's own login (so ``@esbuild`` passes, ``@sindresorhus``
    does not)."""
    eco = component.get("ecosystem") or ""
    group = str(component.get("group") or "")
    token = ""
    if eco == "npm" and group.startswith("@") and len(group) > 1:
        token = group[1:]
    elif eco in _BRAND_GROUP_ECOS and group and "/" not in group:
        token = group
    elif isinstance(data, dict) and isinstance(data.get("namespace"), str):
        token = data["namespace"]
    token = token.strip().lstrip("@")
    if not token or "/" in token or ":" in token:
        return []
    if token.lower() in _NON_BRAND_NAMESPACES:
        return []
    if owner_login and _norm_key(token) == _norm_key(owner_login):
        return []
    return [Candidate(name=token, kind="org", rank=_RANK_BRAND_ORG,
                      source="namespace:brand", form="display")]


def _codemeta_candidates(client: RetryClient, data: dict | None) -> list[Candidate]:
    if not isinstance(data, dict):
        return []
    url = data.get("codemeta_url")
    if not isinstance(url, str) or not url.startswith("http"):
        return []
    doc = _fetch_json(client, url, "packages.ecosyste.ms")
    if not doc:
        return []
    out: list[Candidate] = []
    for key in ("author", "maintainer"):
        entries = doc.get(key)
        if not isinstance(entries, list):
            entries = [entries] if entries else []
        for entry in entries:
            if isinstance(entry, dict):
                found = _clean_name(entry)
                email = _email_of(entry.get("email"))
                entry_type = str(entry.get("@type") or "").lower()
                if not found:
                    if email:
                        out.append(Candidate(name="", kind="person",
                                             rank=_RANK_CODEMETA_PERSON,
                                             source="codemeta", email=email))
                    continue
                if entry_type == "organization":
                    out.append(Candidate(name=found, kind="org",
                                         rank=_RANK_TYPED_ORG, source="codemeta",
                                         form="display", email=email))
                else:
                    out.append(_person(found, _RANK_CODEMETA_PERSON, "codemeta",
                                       email))
            elif isinstance(entry, str):
                found = _clean_name(entry)
                if found:
                    out.append(_person(found, _RANK_CODEMETA_PERSON, "codemeta"))
    for key in ("publisher", "organization"):
        value = doc.get(key)
        if isinstance(value, str):
            found = _clean_name(value)
            if found:
                out.append(Candidate(name=found, kind="org",
                                     rank=_RANK_TYPED_ORG, source="codemeta",
                                     form="display"))
        elif isinstance(value, dict):
            found = _clean_name(value)
            if found:
                out.append(Candidate(name=found, kind="org",
                                     rank=_RANK_TYPED_ORG, source="codemeta",
                                     form="display",
                                     email=_email_of(value.get("email"))))
    return out


def _curated_producer(component: dict) -> str | None:
    """Curated offline producer for a component — longest purl prefix match."""
    if not CURATED_PRODUCERS:
        return None
    ref = str(component.get("purl") or component.get("bom-ref") or "")
    if not ref:
        return None
    for prefix in sorted(CURATED_PRODUCERS, key=len, reverse=True):
        if ref.startswith(prefix):
            producer = str(CURATED_PRODUCERS[prefix] or "").strip()
            if producer:
                return producer
    return None


def _absorb(target: _Entity, other_rank: int, other_form: str, other_name: str,
            other_kind: str, other_email: str, other_sources: list[str],
            index: dict) -> None:
    if other_kind == "org":
        target.kind = "org"
    if other_name and (other_rank, 0 if other_form == "display" else 1) < (
            target.rank, 0 if target.form == "display" else 1):
        target.name = other_name
        target.form = other_form
        index.setdefault(f"n:{_norm_key(other_name)}", target)
    target.rank = min(target.rank, other_rank)
    if other_email and not target.email:
        target.email = other_email
    for source in other_sources:
        if source not in target.sources:
            target.sources.append(source)


def _resolve_entities(candidates: list[Candidate]) -> list[_Entity]:
    """Dedupe candidates into producer entities (email first, then name)."""
    entities: list[_Entity] = []
    index: dict[str, _Entity] = {}
    for cand in candidates:
        keys = []
        if cand.email:
            keys.append(f"e:{cand.email}")
        if cand.name:
            keys.append(f"n:{_norm_key(cand.name)}")
        matched: list[_Entity] = []
        for key in keys:
            found = index.get(key)
            if found is not None and found not in matched:
                matched.append(found)
        if not cand.name:
            for entity in matched:
                if cand.email and not entity.email:
                    entity.email = cand.email
            continue
        if not matched:
            entity = _Entity(name=cand.name, kind=cand.kind, form=cand.form,
                             rank=cand.rank, email=cand.email,
                             sources=[cand.source])
            entities.append(entity)
            for key in keys:
                index.setdefault(key, entity)
            continue
        target = matched[0]
        for extra in matched[1:]:
            _absorb(target, extra.rank, extra.form, extra.name, extra.kind,
                    extra.email, extra.sources, index)
            entities.remove(extra)
            for key, value in list(index.items()):
                if value is extra:
                    index[key] = target
        _absorb(target, cand.rank, cand.form, cand.name, cand.kind,
                cand.email, [cand.source], index)
    return entities


def _pick_winner(entities: list[_Entity]) -> _Entity | None:
    """Organization tier, then person display tier, then login tier."""
    def key(entity: _Entity):
        return (entity.rank, 0 if entity.form == "display" else 1, entity.name)

    orgs = [e for e in entities if e.kind == "org"]
    if orgs:
        return min(orgs, key=key)
    displays = [e for e in entities
                if e.kind == "person" and e.form == "display"]
    if displays:
        return min(displays, key=key)
    if entities:
        return min(entities, key=key)
    return None


def _resolve_supplier(client: RetryClient,
                      component: dict) -> tuple[str, dict] | None:
    """Winner supplier name and its provenance record, or None."""
    curated = _curated_producer(component)
    if curated:
        return curated, {
            "name": curated,
            "sources": ["curated:producers.json"],
            "alternatives": [],
            "method": "curated",
        }

    candidates = _registry_candidates(client, component)
    package_data = _fetch_ecosyste_ms_package(client, component)
    eco_candidates, owner_login = _ecosyste_ms_candidates(client, component,
                                                          package_data)
    candidates.extend(eco_candidates)
    candidates.extend(_brand_candidates(component, package_data, owner_login))
    candidates.extend(_codemeta_candidates(client, package_data))

    entities = _resolve_entities(candidates)
    winner = _pick_winner(entities)
    if winner is None:
        return None
    alternatives = [e.name for e in entities if e is not winner and e.name][:3]
    families = sorted({source.split(":")[0] for source in winner.sources})
    return winner.name, {
        "name": winner.name,
        "sources": sorted(set(winner.sources)),
        "alternatives": alternatives,
        "method": "+".join(families),
    }


def enrich_producers(components: list[dict]) -> list[dict]:
    """Attach a supplier (with provenance) to components lacking one."""
    targets = [(index, comp) for index, comp in enumerate(components)
               if _needs_producer(comp)]
    if not targets:
        return components

    client = RetryClient(timeout=15.0, max_retries=2)
    enriched = 0
    try:
        def work(pair):
            index, comp = pair
            try:
                outcome = _resolve_supplier(client, comp)
            except Exception as e:  # noqa: BLE001 - never break a scan
                logger.debug("producer lookup failed for %s: %s",
                             comp.get("name"), e)
                outcome = None
            return index, comp, outcome

        workers = min(_ENRICH_WORKERS, len(targets))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            for index, comp, outcome in executor.map(work, targets):
                if not outcome:
                    continue
                supplier, evidence = outcome
                existing = comp.get("evidence") or {}
                components[index] = {
                    **comp,
                    "supplier": supplier,
                    "evidence": {**existing, "supplier": evidence},
                }
                enriched += 1
    finally:
        client.close()
    logger.info("Producer enrichment: %d of %d components", enriched, len(targets))
    return components
