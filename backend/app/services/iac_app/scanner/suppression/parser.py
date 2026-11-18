"""Parse inline `# iac:ignore:QUERY_ID` suppression comments."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from app.services.iac_app.scanner.suppression.models import SuppressionRule

COMMENT_PREFIXES = ("#", "//")

IGNORE_TOKEN = re.compile(
    r"iac:ignore:([A-Za-z0-9_.*-]+)",
    re.IGNORECASE,
)
REASON_TOKEN = re.compile(r'reason:\s*[\'"]?([^\'"\n]+?)[\'"]?(?:\s+(?:expiry:|iac:ignore:)|\s*$)', re.IGNORECASE)
EXPIRY_TOKEN = re.compile(r"expiry:\s*(\d{4}-\d{2}-\d{2})", re.IGNORECASE)
ATTR_TOKEN = re.compile(r"\[([^\]]+)\]")


def parse_suppression_comments(source: str, language: str | None = None, file_path: str | None = None) -> list[SuppressionRule]:
    """Parse suppression comments from source text.

    Supported:
      # iac:ignore:AWS.S3.BUCKET_POLICY
      # iac:ignore:AWS.S3.BUCKET_POLICY reason: "public website"
      # iac:ignore:AWS.S3.BUCKET_POLICY expiry: 2025-12-31
      # iac:ignore:AWS.SG.OPEN_CIDR [from_port=22]
      # iac:ignore:AWS.RDS.*
      # iac:ignore:A iac:ignore:B
    """
    del language  # comment syntax is shared across TF/YAML/Dockerfile
    rules: list[SuppressionRule] = []
    for index, raw_line in enumerate(source.splitlines(), start=1):
        line = raw_line.strip()
        if not _is_comment_line(line) and "iac:ignore:" not in line.lower():
            continue
        for query_id in IGNORE_TOKEN.findall(line):
            reason = _first_group(REASON_TOKEN, line)
            expiry = _parse_expiry(_first_group(EXPIRY_TOKEN, line))
            attrs = _parse_attributes(_first_group(ATTR_TOKEN, line))
            rules.append(
                SuppressionRule(
                    query_id=query_id,
                    reason=reason.strip() if reason else None,
                    expiry=expiry,
                    attribute_filter=attrs or None,
                    file_path=file_path,
                    line_number=index,
                    source="inline",
                )
            )
    return rules


def parse_file_suppressions(file_path: str | Path) -> list[SuppressionRule]:
    path = Path(file_path)
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    return parse_suppression_comments(text, file_path=str(path))


def collect_inline_suppressions(files: list[dict]) -> list[SuppressionRule]:
    rules: list[SuppressionRule] = []
    for file_info in files or []:
        path = file_info.get("absolute_path") or file_info.get("path")
        if not path:
            continue
        parsed = parse_file_suppressions(path)
        for rule in parsed:
            if not rule.file_path:
                rule.file_path = file_info.get("path") or path
            elif file_info.get("path"):
                rule.file_path = file_info.get("path")
        rules.extend(parsed)
    return rules


def _is_comment_line(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith(COMMENT_PREFIXES) or "iac:ignore:" in stripped.lower()


def _first_group(pattern: re.Pattern[str], text: str) -> str | None:
    match = pattern.search(text)
    return match.group(1) if match else None


def _parse_expiry(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _parse_attributes(value: str | None) -> dict[str, str]:
    if not value:
        return {}
    attrs: dict[str, str] = {}
    for part in value.split(","):
        if "=" not in part:
            continue
        key, raw = part.split("=", 1)
        attrs[key.strip()] = raw.strip().strip("'\"")
    return attrs
