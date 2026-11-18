"""Load and evaluate `.iacignore` files (Trivy-style ignore list)."""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

from app.services.iac_app.scanner.suppression.models import IgnoreRule

IGNORE_FILENAMES = (".iacignore", ".iac-ignore")


class IacIgnoreFile:
    def __init__(self, root_path: str | Path | None = None, rules: list[IgnoreRule] | None = None):
        self.root_path = Path(root_path) if root_path else None
        self.rules = rules if rules is not None else self._load_ignore_file(self.root_path)

    @classmethod
    def from_text(cls, text: str) -> "IacIgnoreFile":
        return cls(rules=_parse_ignore_text(text))

    def should_ignore(self, finding: dict, file_path: str | None = None) -> bool:
        path = (file_path or finding.get("file_path") or "").replace("\\", "/")
        rule_id = str(finding.get("rule_id") or "")
        severity = str(finding.get("severity") or "").upper()

        for rule in self.rules:
            if rule.kind == "severity" and severity == rule.value.upper():
                return True
            if rule.kind == "query" and _wildcard_match(rule.value, rule_id):
                return True
            if rule.kind == "path" and path and _path_match(rule.value, path):
                return True
        return False

    def _load_ignore_file(self, root_path: Path | None) -> list[IgnoreRule]:
        if root_path is None:
            return []
        root = Path(root_path)
        candidates = [root / name for name in IGNORE_FILENAMES]
        if root.is_file():
            candidates.insert(0, root)
            candidates.extend(root.parent / name for name in IGNORE_FILENAMES)
        for candidate in candidates:
            if candidate.is_file():
                try:
                    return _parse_ignore_text(candidate.read_text(encoding="utf-8", errors="ignore"))
                except OSError:
                    continue
        return []


def _parse_ignore_text(text: str) -> list[IgnoreRule]:
    rules: list[IgnoreRule] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("severity:"):
            value = line.split(":", 1)[1].strip().upper()
            if value:
                rules.append(IgnoreRule(kind="severity", value=value))
            continue
        if _looks_like_path(line):
            rules.append(IgnoreRule(kind="path", value=line.replace("\\", "/")))
            continue
        rules.append(IgnoreRule(kind="query", value=line))
    return rules


def _looks_like_path(value: str) -> bool:
    lowered = value.lower()
    if "/" in value or "\\" in value:
        return True
    return lowered.endswith((".tf", ".yml", ".yaml", ".json", ".tfvars", ".bicep", ".dockerfile"))


def _wildcard_match(pattern: str, value: str) -> bool:
    if not pattern or not value:
        return False
    if pattern == value:
        return True
    return fnmatch.fnmatch(value, pattern)


def _path_match(pattern: str, path: str) -> bool:
    normalized = path.replace("\\", "/").lstrip("./")
    candidate = pattern.replace("\\", "/").lstrip("./")
    if fnmatch.fnmatch(normalized, candidate):
        return True
    if fnmatch.fnmatch(Path(normalized).name, candidate):
        return True
    glob = candidate.replace("**/", "\x00").replace("/**", "\x01").replace("**", "\x02")
    regex = re.escape(glob)
    regex = regex.replace("\x00", "(?:.*/)?").replace("\x01", "(?:/.*)?").replace("\x02", ".*")
    regex = regex.replace(r"\*", "[^/]*")
    if re.fullmatch(regex, normalized):
        return True
    if normalized.endswith(candidate.lstrip("*")):
        return True
    return False
