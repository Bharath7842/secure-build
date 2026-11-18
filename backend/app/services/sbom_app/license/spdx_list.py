import logging
import time
from threading import Lock

import httpx

from ..utils.cache import get_cache

logger = logging.getLogger("sbom.license.spdx_list")

SPDX_LIST_URL = "https://raw.githubusercontent.com/spdx/license-list-data/main/json/licenses.json"
SPDX_RETRY_SECONDS = 60.0


class SPDXLicenseList:
    """SPDX License List - canonical source for license identification and classification."""

    def __init__(self):
        self._by_id: dict[str, dict] = {}
        self._by_name: dict[str, dict] = {}
        self._loaded = False
        self._loading = False
        self._failed_at = 0.0
        self._lock = Lock()

    def _load(self):
        if self._loaded:
            return
        if self._failed_at and time.time() - self._failed_at < SPDX_RETRY_SECONDS:
            return

        waiter = False
        with self._lock:
            if self._loaded:
                return
            if self._loading:
                waiter = True
            else:
                self._loading = True

        if waiter:
            while True:
                with self._lock:
                    if self._loaded or not self._loading:
                        return
                time.sleep(0.05)

        try:
            cache = get_cache()
            cached = cache.get("spdx_license_list")
            if cached:
                self._build_index(cached)
                return

            client = httpx.Client(timeout=15.0)
            try:
                for attempt in range(3):
                    try:
                        resp = client.get(SPDX_LIST_URL)
                        if resp.status_code == 200:
                            data = resp.json()
                            licenses = data.get("licenses", [])
                            cache.set("spdx_license_list", licenses)
                            self._build_index(licenses)
                            logger.info("Loaded %d SPDX licenses", len(licenses))
                            return
                        elif resp.status_code >= 500:
                            time.sleep(1 * (attempt + 1))
                            continue
                        else:
                            logger.warning("SPDX list returned status %d", resp.status_code)
                            return
                    except httpx.TimeoutException:
                        time.sleep(1 * (attempt + 1))
                        continue
            finally:
                client.close()

            logger.warning("Failed to fetch SPDX license list after 3 attempts")
            with self._lock:
                self._failed_at = time.time()
        except Exception as exc:  # noqa: BLE001 - degraded load must not break scans
            with self._lock:
                self._failed_at = time.time()
            logger.warning("SPDX license list load failed: %s", exc)
        finally:
            with self._lock:
                self._loading = False

    def _build_index(self, licenses: list[dict]):
        for lic in licenses:
            if lic.get("isDeprecatedLicenseId"):
                continue
            lid = lic.get("licenseId", "")
            if lid:
                self._by_id[lid] = lic
                name = lic.get("name", "").lower()
                if name:
                    self._by_name[name] = lic
        self._loaded = True

    def get_by_id(self, license_id: str) -> dict | None:
        self._load()
        return self._by_id.get(license_id)

    def get_by_name(self, name: str) -> dict | None:
        self._load()
        return self._by_name.get(name.lower())

    def validate(self, license_id: str) -> bool:
        self._load()
        return license_id in self._by_id

    def is_osi_approved(self, license_id: str) -> bool:
        lic = self.get_by_id(license_id)
        if lic:
            return lic.get("isOsiApproved", False)
        return False

    def get_license_info(self, license_id: str) -> dict | None:
        self._load()
        lic = self._by_id.get(license_id)
        if lic:
            return {
                "licenseId": lic.get("licenseId"),
                "name": lic.get("name"),
                "isOsiApproved": lic.get("isOsiApproved", False),
                "seeAlso": lic.get("seeAlso", []),
            }
        return None

    def match_fuzzy(self, text: str) -> str | None:
        self._load()
        text_lower = text.lower().strip()

        for lid, lic in self._by_id.items():
            name = lic.get("name", "").lower()
            if text_lower == name or text_lower == lid.lower():
                return lid

        best_match = None
        best_score = 0
        for lid, lic in self._by_id.items():
            name = lic.get("name", "").lower()
            if text_lower in name:
                score = len(text_lower) / max(len(name), 1)
                if score > best_score:
                    best_score = score
                    best_match = lid
            elif name in text_lower:
                score = len(name) / max(len(text_lower), 1)
                if score > best_score:
                    best_score = score
                    best_match = lid

        if best_match and best_score > 0.3:
            return best_match

        return None


_spdx_list: SPDXLicenseList | None = None
_spdx_lock = Lock()


def get_spdx_list() -> SPDXLicenseList:
    global _spdx_list
    if _spdx_list is None:
        with _spdx_lock:
            if _spdx_list is None:
                _spdx_list = SPDXLicenseList()
    return _spdx_list
