from urllib.parse import quote, unquote, urlencode

# Ecosystem name -> registered PURL type (https://package-url.github.io/purl/purl-types).
PURL_TYPE_MAP = {
    "maven": "maven",
    "gradle": "maven",
    "kotlin": "maven",
    "npm": "npm",
    "pypi": "pypi",
    "python": "pypi",
    "golang": "golang",
    "go": "golang",
    "cargo": "cargo",
    "rust": "cargo",
    "ruby": "gem",
    "gem": "gem",
    "dart": "pub",
    "pub": "pub",
    "nuget": "nuget",
    "composer": "composer",
    "php": "composer",
    "swift": "swift",
    "conan": "conan",
    "vcpkg": "vcpkg",
    "hex": "hex",
    "elixir": "hex",
    "julia": "julia",
    "docker": "docker",
    "oci": "oci",
    "conda": "conda",
    "apk": "apk",
    "alpine": "apk",
    "deb": "deb",
    "debian": "deb",
    "rpm": "rpm",
    "generic": "generic",
    "sbt": "maven",
    "scala": "maven",
    "clojure": "maven",
    "deno": "npm",
    "r": "cran",
    "cran": "cran",
    "haskell": "hackage",
    "hackage": "hackage",
    "perl": "cpan",
    "cpan": "cpan",
    # No registered PURL type -> generic + `type` qualifier.
    "terraform": "generic",
    "cmake": "generic",
    "cpp": "generic",
    "elm": "generic",
    "crystal": "generic",
}

# Ecosystems that must carry the `type` qualifier when mapped to `generic`.
GENERIC_ECOSYSTEMS = frozenset({"terraform", "cmake", "cpp", "elm", "crystal"})


def generate_purl(component: dict) -> str:
    ecosystem = component.get("ecosystem", "")
    name = component.get("name", "")
    version = component.get("version", "")
    group = component.get("group", "")
    repository = component.get("repository", "")

    # A component may override its purl type (e.g. deno projects mixing npm and
    # jsr packages); the ecosystem map stays the default for everything else.
    purl_type = str(component.get("purl_type") or PURL_TYPE_MAP.get(ecosystem, ecosystem))
    qualifiers: dict[str, str] = {}
    segments: list[str] = []

    if purl_type == "maven":
        if group:
            qualifiers["type"] = "jar"
            segments.append(group)
        segments.append(name)
    elif purl_type == "golang":
        if repository:
            qualifiers["vcs_url"] = repository
        segments.append(f"{group}/{name}" if group else name)
    elif purl_type == "pypi":
        segments.append(quote(name, safe=".-_"))
    elif purl_type == "generic":
        # Unregistered ecosystems carry `type=<ecosystem>` (or an explicit
        # per-component qualifier); namespaces keep their slashes — they are
        # purl path segments, not one name — but are percent-encoded so an
        # `@std` scope still parses as a valid purl path.
        qualifier = component.get("purl_qualifier") or (
            ecosystem if ecosystem in GENERIC_ECOSYSTEMS else ""
        )
        if qualifier:
            qualifiers["type"] = str(qualifier)
        if group:
            segments.append(quote(str(group), safe="-._~"))
        segments.append(quote(str(name), safe="-._~"))
    elif purl_type in ("npm", "docker", "oci", "github"):
        if group:
            segments.append(quote(group, safe=""))
            segments.append(quote(name, safe=""))
        else:
            segments.append(quote(name, safe=""))
    else:
        segments.append(name)

    # §7: the version component is optional — never emit a dangling "@".
    # Raw manifest evidence can be a constraint with spaces ("~> 0.3.1",
    # ">=4.14 && <5"); spaces are illegal in a purl, so they are encoded.
    base = f"pkg:{purl_type}/{'/'.join(segments)}"
    if version:
        base += f"@{str(version).replace(' ', '%20')}"
    return f"{base}?{urlencode(qualifiers)}" if qualifiers else base


def purl_identity(purl: str) -> tuple[str, str, str, str]:
    """Normalized identity ``(type, namespace, name, version)`` of a purl.

    Percent-decoding and qualifier/subpath removal make raw and canonical
    purls of the same package compare equal (an unencoded npm scope
    ``@scope`` and ``%40scope`` share one identity); an unscoped name has
    an empty namespace, and a purl without a version component has an
    empty version.
    """
    base, _, _ = str(purl or "").partition("?")
    base = base.partition("#")[0]
    if not base.startswith("pkg:"):
        return ("", "", "", "")
    ptype, sep, tail = base[4:].partition("/")
    ptype = ptype.lower()
    if not sep:
        return (ptype, "", "", "")
    version = ""
    at = tail.rfind("@")
    if at > 0:
        version = unquote(tail[at + 1:])
        tail = tail[:at]
    parts = [unquote(part) for part in tail.split("/")]
    if len(parts) == 1:
        return (ptype, "", parts[0], version)
    return (ptype, "/".join(parts[:-1]), parts[-1], version)
