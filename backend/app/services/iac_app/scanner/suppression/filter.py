"""Apply inline comments, `.iacignore`, and API/DB suppressions."""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Any, Iterable

from app.services.iac_app.scanner.processing.suppression import apply_suppressions as apply_db_suppressions
from app.services.iac_app.scanner.suppression.ignore_file import IacIgnoreFile
from app.services.iac_app.scanner.suppression.models import SuppressionRule
from app.services.iac_app.scanner.suppression.parser import collect_inline_suppressions


def apply_all_suppressions(
    findings: list[dict],
    *,
    db_suppressions: Iterable[dict[str, Any]] | None = None,
    inline_rules: list[SuppressionRule] | None = None,
    ignore_file: IacIgnoreFile | None = None,
    files: list[dict] | None = None,
    target_path: str | None = None,
) -> list[dict]:
    """Mark matching findings as SUPPRESSED. Findings are not dropped."""
    result = apply_db_suppressions(findings, db_suppressions)

    rules = list(inline_rules or [])
    if files and not inline_rules:
        rules.extend(collect_inline_suppressions(files))

    ignore = ignore_file
    if ignore is None and target_path:
        ignore = IacIgnoreFile(target_path)

    for finding in result:
        if str(finding.get("status") or "").upper() == "SUPPRESSED":
            continue

        if ignore and ignore.should_ignore(finding):
            finding["status"] = "SUPPRESSED"
            finding["suppression_reason"] = "Matched .iacignore"
            finding["suppression_source"] = "iacignore"
            continue

        matched = _match_inline(finding, rules)
        if matched:
            finding["status"] = "SUPPRESSED"
            finding["suppression_reason"] = matched.reason or f"Inline ignore {matched.query_id}"
            finding["suppression_source"] = "inline"

    return result


def _match_inline(finding: dict, rules: list[SuppressionRule]) -> SuppressionRule | None:
    rule_id = str(finding.get("rule_id") or "")
    finding_path = _norm_path(finding.get("file_path") or "")
    finding_line = finding.get("line_start")

    for rule in rules:
        if rule.is_expired():
            continue
        if not _wildcard_match(rule.query_id, rule_id):
            continue
        if rule.file_path and finding_path:
            if not _same_file(rule.file_path, finding_path):
                continue
        if rule.line_number is not None and finding_line is not None:
            if abs(int(finding_line) - int(rule.line_number)) > 3:
                continue
        if rule.attribute_filter and not _attributes_match(finding, rule.attribute_filter):
            continue
        return rule
    return None


def _wildcard_match(pattern: str, value: str) -> bool:
    return bool(pattern) and bool(value) and (pattern == value or fnmatch.fnmatch(value, pattern))


def _same_file(left: str, right: str) -> bool:
    a = _norm_path(left)
    b = _norm_path(right)
    if a == b:
        return True
    return Path(a).name == Path(b).name


def _norm_path(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def _attributes_match(finding: dict, filters: dict[str, Any]) -> bool:
    haystacks = [
        str(finding.get("evidence") or ""),
        str(finding.get("resource") or ""),
        str(finding.get("description") or ""),
    ]
    blob = " ".join(haystacks).lower()
    for key, expected in filters.items():
        token = f"{key}={expected}".lower()
        if token not in blob and str(expected).lower() not in blob:
            return False
    return True
