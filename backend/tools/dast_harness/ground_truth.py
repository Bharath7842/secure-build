"""The ground-truth file format (DAST-16-010 / -020) and its validator.

One file per practice target, tied to the pinned image the expectations were checked against:

    {
      "schema_version": 1,
      "target": "dvwa",
      "image": "ghcr.io/digininja/dvwa@sha256:...",       # the pin in dev/practice-targets/docker-compose.yml
      "verified": false,                                    # true only after every entry was checked by hand
      "preconditions": ["DVWA security level set to 'low'"],
      "rule_packs": ["owasp-web-top10"],                    # the packs the expectations are in scope for
      "expected": [{"check_id": "dast-sqli", "endpoint": "GET /vulnerabilities/sqli/", "param": "id",
                    "source": "documentation", "reference": "...", "needs": ["state_changing"]}],
      "excluded": [{"description": "...", "reason": "business logic"}]
    }

Matching is on `(check id, endpoint path template, parameter)`, the same key the scan-to-scan diff uses.
`excluded` lists vulnerabilities that are real but out of this scanner's scope, so they are never
counted as misses. `verified` must stay false until the entries were checked against the pinned image;
a baseline is never recorded from an unverified file.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from app.dast.domain.dedupe import DedupeKey, key_for

SCHEMA_VERSION = 1
SOURCES = ("documentation", "manual-verification")
NEEDS = ("state_changing", "second_identity", "oast", "schema", "browser_probe", "browser_marker_posts")


@dataclass(frozen=True)
class Expected:
    check_id: str
    endpoint: str  # "METHOD /path/template"
    param: str
    source: str
    reference: str = ""
    needs: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()

    @property
    def key(self) -> DedupeKey:
        return key_for(self.check_id, self.endpoint, self.param or None)


@dataclass(frozen=True)
class GroundTruth:
    target: str
    image: str
    verified: bool
    expected: tuple[Expected, ...]
    excluded: tuple[Mapping[str, str], ...] = ()
    preconditions: tuple[str, ...] = ()
    rule_packs: tuple[str, ...] = ()
    path: str = ""

    def keys(self) -> set[DedupeKey]:
        return {e.key for e in self.expected}


@dataclass
class Validation:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def validate_document(data: Any, *, known_check_ids: set[str] | None = None, pinned_images: set[str] | None = None) -> Validation:
    """Problems with a ground-truth document. `known_check_ids` (the catalog's ids) turns an unknown
    check into an error; `pinned_images` does the same for an image that is not the pinned one."""
    out = Validation()
    if not isinstance(data, Mapping):
        out.errors.append("the document must be a JSON object")
        return out
    if data.get("schema_version") != SCHEMA_VERSION:
        out.errors.append(f"schema_version must be {SCHEMA_VERSION}")
    for key in ("target", "image"):
        if not isinstance(data.get(key), str) or not data[key].strip():
            out.errors.append(f"{key} is required")
    if pinned_images is not None and data.get("image") not in pinned_images:
        out.errors.append(f"image {data.get('image')!r} is not one of the pinned practice-target images")
    if not isinstance(data.get("verified"), bool):
        out.errors.append("verified must be true or false")
    expected = data.get("expected")
    if not isinstance(expected, list):
        out.errors.append("expected must be a list")
        expected = []
    seen: set[DedupeKey] = set()
    for index, item in enumerate(expected):
        where = f"expected[{index}]"
        if not isinstance(item, Mapping):
            out.errors.append(f"{where} must be an object")
            continue
        for key in ("check_id", "endpoint", "source"):
            if not isinstance(item.get(key), str) or not item[key].strip():
                out.errors.append(f"{where}.{key} is required")
        if isinstance(item.get("endpoint"), str) and len(item["endpoint"].split(" ", 1)) != 2:
            out.errors.append(f"{where}.endpoint must look like 'GET /path'")
        if item.get("source") not in SOURCES:
            out.errors.append(f"{where}.source must name where the claim comes from: {', '.join(SOURCES)}")
        if known_check_ids is not None and item.get("check_id") not in known_check_ids:
            out.errors.append(f"{where}.check_id {item.get('check_id')!r} is not a catalog check")
        for need in item.get("needs") or []:
            if need not in NEEDS:
                out.errors.append(f"{where}.needs has unknown item {need!r}")
        if isinstance(item.get("check_id"), str) and isinstance(item.get("endpoint"), str):
            key = key_for(item["check_id"], item["endpoint"], item.get("param") or None)
            if key in seen:
                out.errors.append(f"{where} duplicates an earlier expectation {key}")
            seen.add(key)
    for index, item in enumerate(data.get("excluded") or []):
        if not isinstance(item, Mapping) or not item.get("description") or not item.get("reason"):
            out.errors.append(f"excluded[{index}] needs a description and a reason")
    if data.get("verified") is True and any(isinstance(i, Mapping) and i.get("source") == "documentation" for i in expected):
        out.warnings.append("verified is true but some entries cite only documentation; verify them by hand or mark them manual-verification")
    if data.get("verified") is False:
        out.warnings.append("unverified: the expectations were not checked against the pinned image, so a score from this file is indicative only")
    if not any(isinstance(i, Mapping) and "second_identity" in (i.get("needs") or []) for i in expected):
        out.warnings.append("no multi-role authorization case is listed (acceptable only where the target does not support one)")
    return out


def parse(data: Mapping[str, Any], path: str = "") -> GroundTruth:
    validation = validate_document(data)
    if not validation.ok:
        raise ValueError("invalid ground truth: " + "; ".join(validation.errors))
    return GroundTruth(
        target=data["target"], image=data["image"], verified=bool(data["verified"]),
        expected=tuple(
            Expected(i["check_id"], i["endpoint"], i.get("param") or "", i["source"], i.get("reference", ""), tuple(i.get("needs") or ()), tuple(i.get("roles") or ()))
            for i in data["expected"]
        ),
        excluded=tuple(dict(e) for e in data.get("excluded") or ()), preconditions=tuple(data.get("preconditions") or ()),
        rule_packs=tuple(data.get("rule_packs") or ()), path=path,
    )


def load(path: str | Path) -> GroundTruth:
    with open(path, encoding="utf-8") as handle:
        return parse(json.load(handle), str(path))
