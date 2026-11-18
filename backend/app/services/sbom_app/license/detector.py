import json
import logging
import re
from pathlib import Path

import httpx

from .depsdev import DepsDevClient, SUPPORTED_TYPES as DEPSDEV_SUPPORTED
from .models import (
    COMMUNITY_ENTERPRISE_SOFTWARE,
    KNOWN_LICENSES,
    ComponentClassification,
    CostClassification,
    LicenseInfo,
    LicenseType,
    VendorEdition,
    VendorInfo,
)
from .spdx_list import get_spdx_list
from .text_parser import LicenseTextParser

logger = logging.getLogger("sbom.license.detector")

_CONFIG_DIR = Path(__file__).resolve().parent.parent.parent / "config"


def _load_json_config(filename: str):
    config_path = _CONFIG_DIR / filename
    if config_path.exists():
        with open(config_path, encoding="utf-8") as f:
            return json.load(f)
    return {}


LICENSE_ALIASES = _load_json_config("license_aliases.json")
PROPRIETARY_PATTERNS = _load_json_config("proprietary_patterns.json")
OPEN_SOURCE_INDICATORS = _load_json_config("open_source_indicators.json")

LICENSE_EXCEPTIONS = {
    "universal foss exception, v1.0": "Universal-FOSS-exception-1.0",
    "universal foss exception v1.0": "Universal-FOSS-exception-1.0",
    "universal foss exception": "Universal-FOSS-exception-1.0",
    "universal foss exception, version 1.0": "Universal-FOSS-exception-1.0",
    "classpath exception": "Classpath-exception-2.0",
    "classpath exception 2.0": "Classpath-exception-2.0",
    "classpath-exception-2.0": "Classpath-exception-2.0",
    "gnu classpath exception": "Classpath-exception-2.0",
    "gnu classpath exception 2.0": "Classpath-exception-2.0",
    "gnu classpath, exception": "Classpath-exception-2.0",
    "gnu classpath, exception, version 2.0": "Classpath-exception-2.0",
    "class path exception": "Classpath-exception-2.0",
    "class path exception, version 2.0": "Classpath-exception-2.0",
    "class path exception 2.0": "Classpath-exception-2.0",
}


def _normalize_license_exception(text: str) -> str:
    """Map free-text exception names to their SPDX exception identifiers."""
    key = re.sub(r"\s+", " ", text.strip().lower()).rstrip(".")
    if key in LICENSE_EXCEPTIONS:
        return LICENSE_EXCEPTIONS[key]
    key_no_period = key.replace(".", "")
    for alias, spdx_exception in LICENSE_EXCEPTIONS.items():
        if alias.replace(".", "") == key_no_period:
            return spdx_exception
    return text.strip()


class LicenseDetector:

    LICENSE_FILE_PATTERNS = [
        "LICENSE",
        "LICENSE.txt",
        "LICENSE.md",
        "LICENSE.rst",
        "LICENCE",
        "LICENCE.txt",
        "LICENCE.md",
        "COPYING",
        "COPYING.txt",
        "COPYING.md",
        "LICENSE-MIT",
        "LICENSE-APACHE",
        "LICENSE.APACHE",
        "LICENSE.MIT",
        "LICENSE-bsd",
        "LICENSE-gpl",
        "LICENSE.lgpl",
    ]

    def __init__(self):
        self.client = httpx.Client(timeout=10.0)
        self.text_parser = LicenseTextParser()
        self._depsdev = DepsDevClient()

    def detect_licenses(self, project_path: Path) -> dict[str, LicenseInfo]:
        results: dict[str, LicenseInfo] = {}

        license_files = self._find_license_files(project_path)
        for license_file in license_files:
            license_info = self._parse_license_file(license_file)
            if license_info:
                results[str(license_file.relative_to(project_path))] = license_info

        return results

    def detect_component_license(
        self, component: dict, project_path: Path
    ) -> LicenseInfo:
        declared_license = component.get("license", "")
        purl = component.get("purl", "")
        name = component.get("name", "")

        if declared_license:
            result = self._resolve_license_string(declared_license)
            if result.spdx_id != f"LicenseRef-{declared_license.lower().strip()}":
                return result

        cd_license = component.get("_cd_license", "")
        if cd_license:
            spdx_result = self._validate_spdx(cd_license)
            if spdx_result:
                spdx_result.evidence = f"license expression reported by ClearlyDefined ({cd_license})"
                return spdx_result
            result = self._resolve_license_string(cd_license)
            if result.spdx_id != f"LicenseRef-{cd_license.lower().strip()}":
                result.evidence = f"license expression reported by ClearlyDefined ({cd_license})"
                return result

        if purl:
            purl_type = purl.split("/")[0].replace("pkg:", "") if "/" in purl else ""
            if purl_type in DEPSDEV_SUPPORTED:
                deps_result = self._lookup_depsdev(purl)
                if deps_result:
                    deps_result.evidence = f"license reported by deps.dev for {purl}"
                    return deps_result

        license_info = self._detect_from_license_files(project_path, name)
        if license_info:
            if not license_info.evidence:
                license_info.evidence = f"license text matched in a LICENSE file for {name}"
            return license_info

        return LicenseInfo(
            spdx_id="LicenseRef-unknown",
            name="Unknown License",
            type=LicenseType.UNKNOWN,
            confidence=0.0,
            source="undetected",
        )

    def _validate_spdx(self, spdx_id: str) -> LicenseInfo | None:
        spdx_list = get_spdx_list()
        if spdx_list.validate(spdx_id):
            info = KNOWN_LICENSES.get(spdx_id.lower())
            if info:
                return LicenseInfo(
                    spdx_id=info["spdx_id"],
                    name=info["name"],
                    type=info["type"],
                    confidence=1.0,
                    source="spdx_list",
                )
            lic_info = spdx_list.get_license_info(spdx_id)
            if lic_info:
                license_type = LicenseType.UNKNOWN
                if spdx_list.is_osi_approved(spdx_id):
                    license_type = LicenseType.PERMISSIVE
                return LicenseInfo(
                    spdx_id=lic_info["licenseId"],
                    name=lic_info["name"],
                    type=license_type,
                    confidence=0.95,
                    source="spdx_list",
                )
        return None

    def _detect_from_license_files(
        self, project_path: Path, package_name: str
    ) -> LicenseInfo | None:
        license_files = self._find_license_files(project_path)
        if not license_files:
            return None

        for license_file in license_files[:5]:
            try:
                content = license_file.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            spdx_id = self.text_parser.parse_license_text(license_file)
            if spdx_id:
                info = KNOWN_LICENSES.get(spdx_id.lower())
                if info:
                    return LicenseInfo(
                        spdx_id=info["spdx_id"],
                        name=info["name"],
                        type=info["type"],
                        confidence=0.85,
                        source="license_file",
                    )

        return None

    def classify_component(
        self, component: dict, license_info: LicenseInfo
    ) -> ComponentClassification:
        name = component.get("name", "").lower()
        version = component.get("version", "")
        purl = component.get("purl", "")

        vendor_info = self._get_vendor_info(name)

        if vendor_info:
            edition = vendor_info.edition
            free_features = vendor_info.free_features
            paid_features = vendor_info.paid_features
            vendor = vendor_info.vendor
        else:
            edition = self._infer_edition_from_license(license_info.type)
            free_features = []
            paid_features = []
            vendor = None

        cost_classification = self._determine_cost_classification(
            license_info.type, edition, vendor_info, license_info.confidence
        )

        validation = self._validate_classification(
            name, purl, license_info, cost_classification
        )
        if validation:
            cost_classification = validation

        return ComponentClassification(
            purl=purl,
            name=component.get("name", ""),
            version=version,
            license_type=license_info.type,
            spdx_id=license_info.spdx_id,
            vendor=vendor,
            edition=edition,
            cost_classification=cost_classification,
            free_features=free_features,
            paid_features=paid_features,
        )

    def _validate_classification(
        self,
        name: str,
        purl: str,
        license_info: LicenseInfo,
        current_classification: CostClassification,
    ) -> CostClassification | None:
        if license_info.confidence < 0.3:
            return None

        if current_classification == CostClassification.FULLY_PAID:
            if license_info.type in (
                LicenseType.PERMISSIVE,
                LicenseType.PUBLIC_DOMAIN,
                LicenseType.COPYLEFT,
                LicenseType.WEAK_COPYLEFT,
            ):
                return CostClassification.FULLY_FREE

        if current_classification == CostClassification.FULLY_FREE:
            if license_info.type == LicenseType.PROPRIETARY:
                return CostClassification.FULLY_PAID

        return None

    def _get_vendor_info(self, name: str) -> VendorInfo | None:
        for key, info in COMMUNITY_ENTERPRISE_SOFTWARE.items():
            if _matches_vendor_key(name, key):
                return VendorInfo(
                    vendor=info["vendor"],
                    edition=info["edition"],
                    free_features=info["free_features"],
                    paid_features=info["paid_features"],
                )
        return None

    def _infer_edition_from_license(self, license_type: LicenseType) -> VendorEdition:
        if license_type in (LicenseType.PROPRIETARY,):
            return VendorEdition.COMMERCIAL_ONLY
        elif license_type in (LicenseType.COPYLEFT, LicenseType.WEAK_COPYLEFT):
            return VendorEdition.COMMUNITY_ONLY
        elif license_type in (LicenseType.PERMISSIVE, LicenseType.PUBLIC_DOMAIN):
            return VendorEdition.COMMUNITY_ONLY
        return VendorEdition.UNKNOWN

    def _determine_cost_classification(
        self,
        license_type: LicenseType,
        edition: VendorEdition,
        vendor_info: VendorInfo | None,
        confidence: float = 1.0,
    ) -> CostClassification:
        """Paid-editions semantics: the bucket reflects vendor product editions
        (free tier vs paid tiers), not license copyleft obligations — those are
        reported separately via ``license_type``."""
        if license_type == LicenseType.PROPRIETARY:
            return CostClassification.FULLY_PAID

        if edition == VendorEdition.COMMERCIAL_ONLY:
            return CostClassification.FULLY_PAID

        if vendor_info and vendor_info.paid_features:
            return CostClassification.PARTIALLY_FREE

        if license_type == LicenseType.UNKNOWN:
            return CostClassification.UNKNOWN

        return CostClassification.FULLY_FREE

    def _find_license_files(self, project_path: Path) -> list[Path]:
        license_files = []
        seen = set()
        for pattern in self.LICENSE_FILE_PATTERNS:
            for match in project_path.rglob(pattern):
                if "node_modules" not in str(match) and "vendor" not in str(match):
                    normalized = str(match).lower()
                    if normalized not in seen:
                        seen.add(normalized)
                        license_files.append(match)
        return license_files

    def _parse_license_file(self, license_file: Path) -> LicenseInfo | None:
        try:
            content = license_file.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None

        spdx_id = self.text_parser.parse_license_text(license_file)
        if spdx_id:
            info = KNOWN_LICENSES.get(spdx_id.lower())
            if info:
                return LicenseInfo(
                    spdx_id=info["spdx_id"],
                    name=info["name"],
                    type=info["type"],
                    url=f"https://spdx.org/licenses/{info['spdx_id']}",
                    confidence=0.9,
                    source="license_file",
                )

        content_lower = content.lower()

        if self._is_proprietary_license(content_lower):
            return LicenseInfo(
                spdx_id="LicenseRef-proprietary",
                name="Proprietary License",
                type=LicenseType.PROPRIETARY,
                confidence=0.8,
                source="license_file",
            )

        if "permission is hereby granted, free of charge" in content_lower:
            return LicenseInfo(
                spdx_id="MIT",
                name="MIT License",
                type=LicenseType.PERMISSIVE,
                confidence=0.85,
                source="license_file",
            )

        if "apache license" in content_lower and "version 2.0" in content_lower:
            return LicenseInfo(
                spdx_id="Apache-2.0",
                name="Apache License 2.0",
                type=LicenseType.PERMISSIVE,
                confidence=0.85,
                source="license_file",
            )

        if "gnu lesser general public license" in content_lower:
            if "version 3" in content_lower or "v3" in content_lower:
                return LicenseInfo(
                    spdx_id="LGPL-3.0-only",
                    name="GNU Lesser General Public License v3.0",
                    type=LicenseType.WEAK_COPYLEFT,
                    confidence=0.85,
                    source="license_file",
                )
            return LicenseInfo(
                spdx_id="LGPL-2.1-only",
                name="GNU Lesser General Public License v2.1",
                type=LicenseType.WEAK_COPYLEFT,
                confidence=0.85,
                source="license_file",
            )

        if "gnu general public license" in content_lower:
            if "version 3" in content_lower or "v3" in content_lower:
                return LicenseInfo(
                    spdx_id="GPL-3.0-only",
                    name="GNU General Public License v3.0",
                    type=LicenseType.COPYLEFT,
                    confidence=0.85,
                    source="license_file",
                )
            return LicenseInfo(
                spdx_id="GPL-2.0-only",
                name="GNU General Public License v2.0",
                type=LicenseType.COPYLEFT,
                confidence=0.85,
                source="license_file",
            )

        if "gnu affero general public license" in content_lower:
            return LicenseInfo(
                spdx_id="AGPL-3.0-only",
                name="GNU Affero General Public License v3.0",
                type=LicenseType.COPYLEFT,
                confidence=0.85,
                source="license_file",
            )

        if "mozilla public license" in content_lower:
            return LicenseInfo(
                spdx_id="MPL-2.0",
                name="Mozilla Public License 2.0",
                type=LicenseType.WEAK_COPYLEFT,
                confidence=0.85,
                source="license_file",
            )

        if "eclipse public license" in content_lower:
            if "version 2" in content_lower or "v2" in content_lower:
                return LicenseInfo(
                    spdx_id="EPL-2.0",
                    name="Eclipse Public License 2.0",
                    type=LicenseType.WEAK_COPYLEFT,
                    confidence=0.85,
                    source="license_file",
                )
            return LicenseInfo(
                spdx_id="EPL-1.0",
                name="Eclipse Public License 1.0",
                type=LicenseType.WEAK_COPYLEFT,
                confidence=0.85,
                source="license_file",
            )

        if "creative commons" in content_lower:
            if "zero" in content_lower or "cc0" in content_lower:
                return LicenseInfo(
                    spdx_id="CC0-1.0",
                    name="Creative Commons Zero v1.0",
                    type=LicenseType.PUBLIC_DOMAIN,
                    confidence=0.85,
                    source="license_file",
                )

        if "boost software license" in content_lower:
            return LicenseInfo(
                spdx_id="BSL-1.0",
                name="Boost Software License 1.0",
                type=LicenseType.PERMISSIVE,
                confidence=0.85,
                source="license_file",
            )

        return LicenseInfo(
            spdx_id="LicenseRef-unknown",
            name="Unknown License",
            type=LicenseType.UNKNOWN,
            confidence=0.3,
            source="license_file",
        )

    def _is_proprietary_license(self, content_lower: str) -> bool:
        for pattern in PROPRIETARY_PATTERNS:
            if re.search(pattern, content_lower, re.IGNORECASE):
                for indicator in OPEN_SOURCE_INDICATORS:
                    if re.search(indicator, content_lower, re.IGNORECASE):
                        return False
                return True
        return False

    def _resolve_from_spdx_list(self, license_str: str) -> LicenseInfo | None:
        """Exact SPDX id/name match for declared licenses outside KNOWN_LICENSES."""
        license_id = license_str.strip()
        if not license_id:
            return None
        spdx_list = get_spdx_list()
        info = spdx_list.get_license_info(license_id) or spdx_list.get_by_name(license_id)
        if not info:
            return None
        canonical = info["licenseId"]
        license_type = (
            LicenseType.PERMISSIVE
            if spdx_list.is_osi_approved(canonical)
            else LicenseType.UNKNOWN
        )
        return LicenseInfo(
            spdx_id=canonical,
            name=info["name"],
            type=license_type,
            confidence=0.95,
            source="spdx_list",
        )

    def _resolve_license_string(self, license_str: str) -> LicenseInfo:
        license_lower = license_str.lower().strip()
        license_normalized = re.sub(r"\s+", " ", license_lower)

        for alias, spdx_id in LICENSE_ALIASES.items():
            if alias.lower() == license_normalized or alias.lower() == license_lower:
                info = KNOWN_LICENSES.get(spdx_id.lower())
                if info:
                    return LicenseInfo(
                        spdx_id=info["spdx_id"],
                        name=info["name"],
                        type=info["type"],
                        confidence=0.95,
                        source="declared",
                    )

        for spdx_id, info in KNOWN_LICENSES.items():
            if spdx_id == license_lower or info["name"].lower() == license_lower:
                return LicenseInfo(
                    spdx_id=info["spdx_id"],
                    name=info["name"],
                    type=info["type"],
                    confidence=1.0,
                    source="declared",
                )

        spdx_info = self._resolve_from_spdx_list(license_str)
        if spdx_info:
            return spdx_info

        # Spaced operators only: "\bOR\b" would match the "or" inside ids
        # like "GPL-2.0-or-later" and split on nothing (infinite recursion).
        and_match = re.search(r"\s+AND\s+", license_str, re.IGNORECASE)
        or_match = re.search(r"\s+OR\s+", license_str, re.IGNORECASE)

        if and_match or or_match:
            if and_match and or_match:
                and_pos = and_match.start()
                or_pos = or_match.start()
                operator = "AND" if and_pos < or_pos else "OR"
            elif and_match:
                operator = "AND"
            else:
                operator = "OR"

            parts = re.split(r"\s+%s\s+" % operator, license_str, flags=re.IGNORECASE)
            resolved_parts = []
            for part in parts:
                resolved = self._resolve_license_string(part.strip())
                if resolved.spdx_id != f"LicenseRef-{part.strip().lower()}":
                    resolved_parts.append(resolved)

            if len(parts) > 1 and resolved_parts:
                primary = resolved_parts[0]
                combined_spdx = (" %s " % operator).join(p.spdx_id for p in resolved_parts)
                license_type = primary.type
                if operator == "OR":
                    for p in resolved_parts:
                        if p.type in (LicenseType.PERMISSIVE, LicenseType.PUBLIC_DOMAIN):
                            license_type = p.type
                            break
                return LicenseInfo(
                    spdx_id=combined_spdx,
                    name=license_str,
                    type=license_type,
                    confidence=0.8,
                    source="declared",
                    evidence=f'declared SPDX expression: "{license_str}"',
                )

        with_match = re.search(r"\bWITH\b", license_str, re.IGNORECASE)
        if with_match:
            base_str, exception_str = re.split(
                r"\s+WITH\s+", license_str, maxsplit=1, flags=re.IGNORECASE
            )
            base = self._resolve_license_string(base_str.strip())
            if base.spdx_id and not base.spdx_id.startswith("LicenseRef-"):
                exception = _normalize_license_exception(exception_str)
                license_type = base.type
                if license_type == LicenseType.COPYLEFT:
                    # A linking/distribution exception relaxes copyleft for
                    # consumers (classpath, Universal FOSS, ...).
                    license_type = LicenseType.WEAK_COPYLEFT
                return LicenseInfo(
                    spdx_id=f"{base.spdx_id} WITH {exception}",
                    name=license_str,
                    type=license_type,
                    confidence=base.confidence,
                    source="declared",
                    evidence=f'SPDX license expression with exception: "{license_str}"',
                )

        if self._is_proprietary_license(license_lower):
            return LicenseInfo(
                spdx_id="LicenseRef-proprietary",
                name=license_str,
                type=LicenseType.PROPRIETARY,
                confidence=0.7,
                source="declared",
            )

        for spdx_id, info in KNOWN_LICENSES.items():
            if spdx_id in license_lower:
                return LicenseInfo(
                    spdx_id=info["spdx_id"],
                    name=info["name"],
                    type=info["type"],
                    confidence=0.7,
                    source="declared",
                )

        for alias, target_spdx in LICENSE_ALIASES.items():
            if alias in license_lower:
                info = KNOWN_LICENSES.get(target_spdx.lower())
                if info:
                    return LicenseInfo(
                        spdx_id=info["spdx_id"],
                        name=info["name"],
                        type=info["type"],
                        confidence=0.7,
                        source="declared",
                    )

        return LicenseInfo(
            spdx_id=f"LicenseRef-{license_lower}",
            name=license_str,
            type=LicenseType.UNKNOWN,
            confidence=0.3,
            source="declared",
        )

    def _lookup_depsdev(self, purl: str) -> LicenseInfo | None:
        try:
            result = self._depsdev.lookup_by_purl(purl)
            if not result:
                return None

            # Preferred: resolve every license deps.dev reported (names and
            # SPDX ids alike) as one expression, so dual licenses and
            # exceptions survive intact.
            expression = str(result.get("expression") or "")
            if expression:
                resolved = self._resolve_license_string(expression)
                if resolved.spdx_id != f"LicenseRef-{expression.lower().strip()}":
                    return resolved

            spdx_id = result.get("spdx_id", "")
            if spdx_id and spdx_id != "non-standard":
                spdx_result = self._validate_spdx(spdx_id)
                if spdx_result:
                    return spdx_result
                resolved = self._resolve_license_string(spdx_id)
                if resolved.spdx_id != f"LicenseRef-{spdx_id.lower().strip()}":
                    return resolved
                return None

            # deps.dev reports many maven licenses as "non-standard" SPDX but
            # still names them (e.g. "Eclipse Public License - v 1.0") — resolve
            # the human names rather than dropping the package to unknown.
            # Multiple names are an OR-choice of licenses (logback: EPL or LGPL).
            names = list(dict.fromkeys(
                detail.get("license", "")
                for detail in result.get("license_details", [])
                if detail.get("license")
            ))
            if not names:
                raw = result.get("raw_license", "")
                names = [raw] if raw else []
            if names:
                candidate = " OR ".join(names) if len(names) > 1 else names[0]
                resolved = self._resolve_license_string(candidate)
                if resolved.spdx_id != f"LicenseRef-{candidate.lower().strip()}":
                    return resolved
        except Exception as e:
            logger.debug("deps.dev lookup failed for %s: %s", purl, e)
        return None

    def close(self):
        self.client.close()
        self._depsdev.close()


def _normalize_name(name: str) -> str:
    normalized = name.lower()
    if "/" in normalized:
        parts = normalized.split("/")
        normalized = parts[-1]
    if normalized.startswith("@"):
        parts = normalized.split("/")
        if len(parts) > 1:
            normalized = parts[-1]
    return normalized


def _matches_vendor_key(name: str, key: str) -> bool:
    name_lower = _normalize_name(name)
    key_lower = key.lower()

    if name_lower == key_lower:
        return True

    if len(key_lower) <= 4:
        return False

    if key_lower.startswith(name_lower):
        rest = key_lower[len(name_lower):]
        if rest and rest[0] in "-_.":
            return True

    if name_lower.startswith(key_lower):
        rest = name_lower[len(key_lower):]
        if rest and rest[0] in "-_.":
            return True

    if name_lower.replace("-", "").replace("_", "") == key_lower.replace("-", "").replace("_", ""):
        return True

    if name_lower.replace("_", "") == key_lower.replace("_", ""):
        return True

    return False
