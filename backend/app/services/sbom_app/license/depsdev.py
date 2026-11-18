import json
import logging
import time
from urllib.parse import quote

from ..utils.rate_limiter import RetryClient, rate_limit_request

logger = logging.getLogger("sbom.license.depsdev")

DEPSDEV_BASE = "https://api.deps.dev/v3alpha"

DEPSDEV_SYSTEM_MAP = {
    "npm": "NPM",
    "pypi": "PYPI",
    "cargo": "CARGO",
    "maven": "MAVEN",
    "golang": "GOLANG",
    "nuget": "NUGET",
}

SUPPORTED_TYPES = set(DEPSDEV_SYSTEM_MAP.keys())

CACHE_TTL = 3600  # 1 hour in seconds


class DepsDevClient:

    def __init__(self, client: RetryClient | None = None):
        self._client = client or RetryClient(timeout=15.0, max_retries=3)
        self._cache: dict[str, tuple[float, dict | None]] = {}

    def lookup_by_purl(self, purl: str) -> dict | None:
        now = time.time()
        if purl in self._cache:
            cached_time, cached_result = self._cache[purl]
            if now - cached_time < CACHE_TTL:
                return cached_result

        purl_type = _extract_purl_type(purl)
        if purl_type not in SUPPORTED_TYPES:
            return None

        encoded = quote(_strip_qualifiers(purl), safe="")
        url = f"{DEPSDEV_BASE}/purl/{encoded}"

        rate_limit_request("api.deps.dev")
        resp = self._client.get(url, headers={"Accept": "application/json"})

        if resp is None:
            self._cache[purl] = (now, None)
            return None
        if resp.status_code == 429:
            logger.warning("deps.dev rate limited for %s", purl)
            self._cache[purl] = (now, None)
            return None
        if resp.status_code != 200:
            logger.debug("deps.dev returned %d for %s", resp.status_code, purl)
            self._cache[purl] = (now, None)
            return None

        try:
            data = resp.json()
            version = data.get("version")
            if not version:
                self._cache[purl] = (now, None)
                return None
            result = _parse_version(version)
            self._cache[purl] = (now, result)
            return result
        except Exception as e:
            logger.warning("Failed to parse deps.dev response for %s: %s", purl, e)
            self._cache[purl] = (now, None)
            return None

    def batch_lookup(self, purls: list[str]) -> dict[str, dict]:
        now = time.time()
        results = {}
        uncached_purls = []

        for purl in purls:
            if purl in self._cache:
                cached_time, cached_result = self._cache[purl]
                if now - cached_time < CACHE_TTL:
                    if cached_result:
                        results[purl] = cached_result
                    continue
            uncached_purls.append(purl)

        by_stripped: dict[str, str] = {}
        for purl in uncached_purls:
            if _extract_purl_type(purl) in SUPPORTED_TYPES:
                by_stripped.setdefault(_strip_qualifiers(purl), purl)

        batch_size = 100
        stripped_names = list(by_stripped)
        for i in range(0, len(stripped_names), batch_size):
            batch = stripped_names[i:i + batch_size]
            batch_results = self._batch_lookup_chunk(batch)
            for stripped, result in batch_results.items():
                purl = by_stripped.get(stripped, stripped)
                results[purl] = result
                self._cache[purl] = (now, result)

        return results

    def _batch_lookup_chunk(self, purls: list[str]) -> dict[str, dict]:
        if not purls:
            return {}

        requests = [{"purl": p} for p in purls]
        url = f"{DEPSDEV_BASE}/purlbatch"

        rate_limit_request("api.deps.dev")
        resp = self._client.post(
            url,
            json={"requests": requests},
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )

        if resp is None or resp.status_code != 200:
            logger.warning("deps.dev batch lookup failed (status=%s)", resp.status_code if resp else "None")
            return {}

        try:
            data = resp.json()
            results = {}
            for item in data.get("responses", []):
                req = item.get("request", {})
                result = item.get("result", {})
                version = result.get("version")
                purl = req.get("purl", "")
                if purl and version:
                    results[purl] = _parse_version(version)
            return results
        except Exception as e:
            logger.warning("Failed to parse deps.dev batch response: %s", e)
            return {}

    def close(self):
        self._client.close()


def _extract_purl_type(purl: str) -> str:
    if not purl.startswith("pkg:"):
        return ""
    remainder = purl[4:]
    slash = remainder.find("/")
    if slash <= 0:
        return ""
    return remainder[:slash]


def _strip_qualifiers(purl: str) -> str:
    """deps.dev identifies artifacts without purl qualifiers (`?type=jar`,
    which its purl endpoint rejects with 400)."""
    return purl.split("?", 1)[0]


# deps.dev uses its own identifiers for a few well-known license combos.
SPDX_ID_FIXUPS = {
    "GPL-2.0-with-classpath-exception": "GPL-2.0-only WITH Classpath-exception-2.0",
}


def _parse_version(version: dict) -> dict:
    licenses = version.get("licenses", [])
    license_details = version.get("licenseDetails", [])

    spdx_id = ""
    raw_license = ""
    entries: list[str] = []

    for detail in license_details:
        detail_spdx = detail.get("spdx", "")
        detail_name = detail.get("license", "")
        if detail_spdx and detail_spdx != "non-standard":
            entries.append(SPDX_ID_FIXUPS.get(detail_spdx, detail_spdx))
        elif detail_name:
            entries.append(detail_name)

    if license_details:
        for detail in license_details:
            spdx = detail.get("spdx", "")
            if spdx and spdx != "non-standard":
                spdx_id = SPDX_ID_FIXUPS.get(spdx, spdx)
                raw_license = detail.get("license", "")
                break
        if not spdx_id and license_details:
            raw_license = license_details[0].get("license", "")

    if not entries:
        for lic in licenses:
            if lic and lic != "non-standard":
                fixed = SPDX_ID_FIXUPS.get(lic, lic)
                entries.append(fixed)
                if not spdx_id:
                    spdx_id = fixed
                    raw_license = lic
                break
        if not entries and licenses:
            raw_license = raw_license or licenses[0]
    elif not raw_license:
        raw_license = entries[0]

    return {
        "spdx_id": spdx_id,
        "raw_license": raw_license,
        # Every license deps.dev reported, in order — deps.dev often lists a
        # dual license as one "non-standard" name plus one SPDX id, and both
        # must survive into the resolved expression.
        "expression": " OR ".join(dict.fromkeys(entries)),
        "licenses": licenses,
        "license_details": license_details,
        "source": "deps.dev",
    }
