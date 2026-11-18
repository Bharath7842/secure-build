import logging
import re
from urllib.parse import quote

import httpx

from ..utils.rate_limiter import rate_limit_request, RetryClient
from ..utils.cache import get_cache

logger = logging.getLogger("sbom.license.clearlydefined")

CD_API_BASE = "https://api.clearlydefined.io"
CD_DEFINITIONS_URL = f"{CD_API_BASE}/definitions"
CD_BATCH_URL = f"{CD_API_BASE}/definitions"

PURL_TO_CD_MAP = {
    "npm": "npm/npmjs/-/{name}/{version}",
    "pypi": "pypi/pypi/-/{name}/{version}",
    "maven": "maven/mavencentral/{group}/{name}/{version}",
    "golang": "go/golang/{group}/{name}/{version}",
    "cargo": "crate/cratesio/-/{name}/{version}",
    "nuget": "nuget/nuget/-/{name}/{version}",
    "composer": "composer/packagist/{group}/{name}/{version}",
    "gem": "gem/rubygems/-/{name}/{version}",
    "swift": "swift/github/-/{name}/{version}",
    "pub": "pub/dartpub/-/{name}/{version}",
}


def purl_to_cd_coordinates(purl: str) -> str | None:
    if not purl:
        return None

    parts = purl.split("/")
    if len(parts) < 2:
        return None

    type_part = parts[0].replace("pkg:", "")
    rest = "/".join(parts[1:])

    version_match = re.search(r"@([^@]+)$", rest)
    if not version_match:
        return None

    version = version_match.group(1)
    name_path = rest[: version_match.start()]

    if type_part == "maven":
        segments = name_path.split("/")
        if len(segments) >= 2:
            group = "/".join(segments[:-1])
            name = segments[-1]
        else:
            group = ""
            name = name_path
        return f"maven/mavencentral/{group}/{name}/{version}"

    elif type_part == "golang":
        segments = name_path.split("/")
        if len(segments) >= 2:
            group = "/".join(segments[:-1])
            name = segments[-1]
        else:
            group = ""
            name = name_path
        return f"go/golang/{group}/{name}/{version}"

    elif type_part == "composer":
        segments = name_path.split("/")
        if len(segments) >= 2:
            group = "/".join(segments[:-1])
            name = segments[-1]
        else:
            group = ""
            name = name_path
        return f"composer/packagist/{group}/{name}/{version}"

    elif type_part == "npm":
        if name_path.startswith("@"):
            slash_idx = name_path.index("/")
            namespace = name_path[:slash_idx]
            name = name_path[slash_idx + 1 :]
            return f"npm/npmjs/{namespace}/{name}/{version}"
        return f"npm/npmjs/-/{name_path}/{version}"

    elif type_part == "pypi":
        return f"pypi/pypi/-/{name_path}/{version}"

    elif type_part == "cargo":
        return f"crate/cratesio/-/{name_path}/{version}"

    elif type_part == "nuget":
        return f"nuget/nuget/-/{name_path}/{version}"

    elif type_part == "gem":
        return f"gem/rubygems/-/{name_path}/{version}"

    elif type_part == "swift":
        return f"swift/github/-/{name_path}/{version}"

    elif type_part == "pub":
        return f"pub/dartpub/-/{name_path}/{version}"

    template = PURL_TO_CD_MAP.get(type_part)
    if template:
        group = ""
        name = name_path
        if "/" in name_path:
            segments = name_path.split("/")
            group = "/".join(segments[:-1])
            name = segments[-1]
        return template.format(name=name, version=version, group=group)

    return None


_retry_client = RetryClient(timeout=10.0, max_retries=3)


def lookup_license(purl: str, http_client: httpx.Client | None = None) -> dict | None:
    cache = get_cache()
    cache_key = f"cd:{purl}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    coordinates = purl_to_cd_coordinates(purl)
    if not coordinates:
        return None

    url = f"{CD_DEFINITIONS_URL}/{coordinates}"

    try:
        rate_limit_request("api.clearlydefined.io")
        resp = _retry_client.get(url)
        if resp and resp.status_code == 200:
            data = resp.json()
            result = _parse_definition(data)
            if result:
                cache.set(cache_key, result)
            return result
        return None
    except Exception as e:
        logger.warning("ClearlyDefined lookup failed for %s: %s", purl, e)
        return None


def batch_lookup(purls: list[str], http_client: httpx.Client | None = None) -> dict[str, dict | None]:
    cache = get_cache()
    results = {}
    uncached = []

    for purl in purls:
        cache_key = f"cd:{purl}"
        cached = cache.get(cache_key)
        if cached is not None:
            results[purl] = cached
        else:
            uncached.append(purl)

    if not uncached:
        return results

    coordinates_list = []
    purl_map = {}
    for purl in uncached:
        coords = purl_to_cd_coordinates(purl)
        if coords:
            coordinates_list.append({"coordinates": coords})
            purl_map[coords] = purl

    if not coordinates_list:
        return results

    batch_size = 50
    for i in range(0, len(coordinates_list), batch_size):
        batch = coordinates_list[i : i + batch_size]

        try:
            rate_limit_request("api.clearlydefined.io")
            resp = _retry_client.post(CD_BATCH_URL, json=batch)
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                except Exception:
                    data = []
                if isinstance(data, list):
                    for item in data:
                        if not isinstance(item, dict):
                            continue
                        coords = item.get("coordinates", "")
                        purl = purl_map.get(coords)
                        if purl:
                            result = _parse_definition(item)
                            results[purl] = result
                            if result:
                                cache_key = f"cd:{purl}"
                                cache.set(cache_key, result)
        except Exception as e:
            logger.warning("ClearlyDefined batch lookup failed: %s", e)

    for purl in uncached:
        if purl not in results:
            results[purl] = None

    return results


def _parse_definition(data: dict) -> dict | None:
    if not data:
        return None

    licensed = data.get("licensed", {})
    declared = licensed.get("declared", "")
    discovered = licensed.get("discovered", [])

    expressions = licensed.get("expressions", [])
    spdx_expressions = []
    for expr in expressions:
        if isinstance(expr, dict):
            spdx_expressions.append(expr.get("expression", ""))
        elif isinstance(expr, str):
            spdx_expressions.append(expr)

    if declared:
        license_id = declared
    elif spdx_expressions:
        license_id = spdx_expressions[0]
    elif discovered:
        license_id = discovered[0].get("license", "") if isinstance(discovered[0], dict) else ""
    else:
        return None

    if not license_id or license_id in ("NOASSERTION", "NONE", "OTHER", ""):
        return None

    return {
        "spdx_id": license_id,
        "declared": declared,
        "discovered": [d.get("license", "") if isinstance(d, dict) else str(d) for d in discovered],
        "expressions": spdx_expressions,
        "score": data.get("score", {}),
    }
