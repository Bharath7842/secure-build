"""Loads the DAST vulnerability coverage matrix from `app/data/dast/vulnerability_coverage.yaml`
for the settings page's coverage view. Pure reporting: it never gates or changes scan behaviour.

Every `check_ids` entry is cross-checked against the real check catalog so the matrix cannot
silently drift to reference a check id that no longer exists (or never did).
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from app.services.dast_catalog import DATA_DIR, default_catalog

COVERAGE_FILE = "vulnerability_coverage.yaml"
VALID_STATUSES = {"full", "partial", "dormant", "none", "not_applicable"}


class CoverageLoadError(ValueError):
    def __init__(self, issues: list[str]):
        self.issues = tuple(issues)
        super().__init__("vulnerability coverage matrix failed to load:\n  " + "\n  ".join(issues))


def _load_raw(data_dir: Path) -> dict[str, Any]:
    path = data_dir / COVERAGE_FILE
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CoverageLoadError([f"cannot read {path.name}: {exc}"]) from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise CoverageLoadError([f"invalid YAML in {path.name}: {exc}"]) from exc
    if not isinstance(data, dict) or not isinstance(data.get("categories"), list):
        raise CoverageLoadError([f"{path.name}: expected a top-level mapping with a 'categories' list"])
    return data


def load_coverage(data_dir: Path = DATA_DIR) -> dict[str, Any]:
    """Validated `{generated_from, categories: [{category, items: [...]}]}`, with each item's
    `check_ids` resolved to `{id, title, severity, mode}` from the live catalog."""
    raw = _load_raw(data_dir)
    catalog_by_id = {c.check_id: c for c in default_catalog().checks}
    for c in default_catalog().checks:
        for alias in c.aliases:
            catalog_by_id.setdefault(alias, c)

    issues: list[str] = []
    categories: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for cat in raw["categories"]:
        if not isinstance(cat, dict) or "category" not in cat or not isinstance(cat.get("items"), list):
            issues.append(f"malformed category entry: {cat!r}")
            continue
        items_out = []
        for item in cat["items"]:
            if not isinstance(item, dict):
                issues.append(f"{cat['category']}: malformed item {item!r}")
                continue
            item_id = item.get("id")
            if not item_id or item_id in seen_ids:
                issues.append(f"{cat['category']}: missing or duplicate item id {item_id!r}")
                continue
            seen_ids.add(item_id)
            status = item.get("status")
            if status not in VALID_STATUSES:
                issues.append(f"{item_id}: unknown status {status!r}")
                continue
            resolved_checks = []
            for check_id in item.get("check_ids") or []:
                check = catalog_by_id.get(check_id)
                if check is None:
                    issues.append(f"{item_id}: references unknown check id {check_id!r}")
                    continue
                resolved_checks.append({"id": check.check_id, "title": check.title, "severity": check.base_severity.value, "mode": check.mode.value})
            items_out.append(
                {
                    "id": item_id,
                    "name": item.get("name", item_id),
                    "status": status,
                    "checks": resolved_checks,
                    "note": item.get("note"),
                }
            )
        categories.append({"category": cat["category"], "items": items_out})

    if issues:
        raise CoverageLoadError(issues)
    return {"generated_from": raw.get("generated_from"), "categories": categories}


@lru_cache(maxsize=1)
def default_coverage() -> dict[str, Any]:
    return load_coverage()
