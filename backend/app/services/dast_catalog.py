"""Loads the DAST check catalog, rule packs and remediation text from `app/data/dast/`
(DAST-03-010). The validation itself is pure and lives in `app.dast.domain.catalog`; this
module owns the file reading and turns issues into errors that name the file and line.

A catalog that fails to load raises `CatalogLoadError` listing every problem, so a bad edit is
reported whole instead of one error at a time.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Sequence

import yaml

from app.dast.domain.catalog import Catalog, CatalogIssue, PackDef, parse_check, parse_checks, parse_packs
from app.dast.domain.detectors import signal_names
from app.dast.domain.entities import Check

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "dast"
CATALOG_FILE = "check_catalog.yaml"
PACKS_FILE = "rule_packs.yaml"
REMEDIATION_DIR = "remediation"
CUSTOM_REMEDIATION_REF = "rem-custom"  # generic guidance for a rule that names no remediation file
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")


@dataclass(frozen=True)
class LocatedIssue:
    file: str
    line: int | None
    message: str

    def __str__(self) -> str:
        where = f"{self.file}:{self.line}" if self.line else self.file
        return f"{where}: {self.message}"


class CatalogLoadError(ValueError):
    def __init__(self, issues: Sequence[LocatedIssue]):
        self.issues = tuple(issues)
        super().__init__("check catalog failed to load:\n  " + "\n  ".join(str(i) for i in self.issues))


def remediation_path(ref: str, data_dir: Path = DATA_DIR) -> Path | None:
    """File for a remediation reference, or None when the reference is malformed."""
    if not _REF.match(ref or ""):
        return None
    return data_dir / REMEDIATION_DIR / f"{ref}.md"


def remediation_exists(ref: str, data_dir: Path = DATA_DIR) -> bool:
    path = remediation_path(ref, data_dir)
    return path is not None and path.is_file()


def remediation_text(ref: str, data_dir: Path = DATA_DIR) -> str:
    """Remediation guidance for a finding. "" when the reference does not resolve."""
    path = remediation_path(ref, data_dir)
    if path is None or not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        logger.warning("could not read remediation file %s", path)
        return ""


def _item_lines(text: str) -> list[int]:
    """1-based line of each top-level list item (empty when the document is not a list)."""
    try:
        node = yaml.compose(text)
    except yaml.YAMLError:
        return []
    if not isinstance(node, yaml.SequenceNode):
        return []
    return [item.start_mark.line + 1 for item in node.value]


def _located(file: str, lines: Sequence[int], issue: CatalogIssue) -> LocatedIssue:
    line = lines[issue.index] if 0 <= issue.index < len(lines) else None
    who = f"{issue.check_id}: " if issue.check_id else ""
    return LocatedIssue(file, line, who + issue.message)


def _read_yaml_list(path: Path) -> tuple[list[Any], list[int], list[LocatedIssue]]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [], [], [LocatedIssue(path.name, None, f"cannot read file: {exc}")]
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        return [], [], [LocatedIssue(path.name, (mark.line + 1) if mark else None, f"invalid YAML: {exc}")]
    if data is None:
        data = []
    if not isinstance(data, list):
        return [], [], [LocatedIssue(path.name, 1, "expected a list at the top level")]
    return data, _item_lines(text), []


def load_catalog(data_dir: Path = DATA_DIR) -> Catalog:
    """Read, validate and return the catalog. Raises `CatalogLoadError` on any fatal problem."""
    problems: list[LocatedIssue] = []
    raw_checks, lines, errs = _read_yaml_list(data_dir / CATALOG_FILE)
    problems.extend(errs)
    result = parse_checks(
        raw_checks,
        signal_names=signal_names(),
        remediation_exists=lambda ref: remediation_exists(ref, data_dir),
    )
    problems.extend(_located(CATALOG_FILE, lines, i) for i in result.errors)

    raw_packs, pack_lines, errs = _read_yaml_list(data_dir / PACKS_FILE)
    problems.extend(errs)
    packs, pack_errors = parse_packs(raw_packs, [c.check_id for c in result.checks] + [a for c in result.checks for a in c.aliases])
    problems.extend(LocatedIssue(PACKS_FILE, None, message) for message in pack_errors)
    if problems:
        raise CatalogLoadError(problems)
    for note in result.notes:
        logger.warning("catalog: %s", _located(CATALOG_FILE, lines, note))
    return Catalog(result.checks, packs, tuple(result.notes))


@lru_cache(maxsize=1)
def default_catalog() -> Catalog:
    return load_catalog()


def catalog_version(data_dir: Path = DATA_DIR) -> str:
    """Short content hash of the catalog and pack files, recorded in scan snapshots."""
    digest = hashlib.sha256()
    for name in (CATALOG_FILE, PACKS_FILE):
        try:
            digest.update((data_dir / name).read_bytes())
        except OSError:
            digest.update(b"-")
    return digest.hexdigest()[:12]


# ---- single checks from YAML text (custom rules) ----------------------------------------------


def parse_check_yaml(
    text: str, *, source: str = "custom", version: int = 1, data_dir: Path = DATA_DIR
) -> tuple[Check | None, list[LocatedIssue], list[str]]:
    """Validate one check supplied as YAML text. Returns (check or None, errors, notes)."""
    errors: list[LocatedIssue] = []
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        return None, [LocatedIssue("rule", (mark.line + 1) if mark else None, f"invalid YAML: {exc}")], []
    if isinstance(data, list) and len(data) == 1:
        data = data[0]
    if not isinstance(data, dict):
        return None, [LocatedIssue("rule", 1, "a rule must be a single YAML mapping")], []
    check, issues = parse_check(
        data, 0, signal_names=signal_names(), remediation_exists=lambda ref: remediation_exists(ref, data_dir),
        source=source, version=version, strict_signals=True, default_remediation_ref=CUSTOM_REMEDIATION_REF,
    )
    errors = [LocatedIssue("rule", None, i.message) for i in issues if i.fatal]
    notes = [i.message for i in issues if not i.fatal]
    return (None if errors else check), errors, notes
