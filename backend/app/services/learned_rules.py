"""Per-project store of agentic-hunt learned rules.

The hunt promotes a search pattern to a rule only after its own gates
(sast_engine/pipeline/hunt/learned.py: matches every confirmed sink it led
to, no refuted/disputed site, under a repo-wide noise ceiling). A successful
scan merges those promotions into `Project.learned_rules`; the next scan
passes them to the engine, which runs them with the regex catalog (limitation
`learned-hunt-rules`). Removing one is `DELETE /projects/{id}/learned-rules/{rule_id}`.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any

MAX_LEARNED_RULES_PER_PROJECT = 50
_RULE_FIELDS = ("title", "description", "cwe", "severity", "pattern", "languages")


def learned_rule_id(cwe: str | None, pattern: str) -> str:
    """Stable across scans, so the same pattern promoted twice is one rule."""
    digest = hashlib.sha1(pattern.encode("utf-8")).hexdigest()[:10]
    return f"learned-{(cwe or 'cwe').strip().lower()}-{digest}"


def promoted_rules(discovery: dict | None) -> list[dict[str, Any]]:
    report = (discovery or {}).get("report") or {}
    rows = ((report.get("hunt") or {}).get("learned_rules")) or []
    return [r for r in rows if isinstance(r, dict) and r.get("status") == "promoted" and r.get("rule")]


def merge_promoted_rules(
    existing: list[dict[str, Any]] | None,
    discovery: dict | None,
    *,
    scan_id: str,
    now: datetime | None = None,
) -> list[dict[str, Any]] | None:
    """The project's rule list with this scan's promotions merged in, or
    None when nothing changed. Newest first, capped, deduped by pattern."""
    current = [dict(r) for r in (existing or []) if isinstance(r, dict) and r.get("pattern")]
    by_pattern = {r["pattern"]: r for r in current}
    stamp = (now or datetime.now(timezone.utc)).isoformat()
    added = False
    for row in promoted_rules(discovery):
        rule = row["rule"]
        pattern = str(rule.get("pattern") or "")
        try:
            re.compile(pattern)
        except re.error:
            continue
        if not pattern or pattern in by_pattern:
            if pattern in by_pattern:
                # Re-confirmed on a later scan: refresh its provenance.
                by_pattern[pattern]["last_confirmed_scan_id"] = scan_id
                by_pattern[pattern]["last_confirmed_at"] = stamp
                added = True
            continue
        entry = {k: rule.get(k) for k in _RULE_FIELDS}
        entry.update({
            "id": learned_rule_id(rule.get("cwe"), pattern),
            "derived": True,
            "learned_from_scan_id": scan_id,
            "learned_at": stamp,
            "last_confirmed_scan_id": scan_id,
            "last_confirmed_at": stamp,
            "positives": list(row.get("positives") or [])[:10],
        })
        current.insert(0, entry)
        by_pattern[pattern] = entry
        added = True
    if not added:
        return None
    current.sort(key=lambda r: str(r.get("last_confirmed_at") or ""), reverse=True)
    return current[:MAX_LEARNED_RULES_PER_PROJECT]
