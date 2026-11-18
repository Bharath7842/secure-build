"""Suppression rule models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class SuppressionRule:
    query_id: str
    reason: str | None = None
    expiry: datetime | None = None
    attribute_filter: dict[str, Any] | None = None
    file_path: str | None = None
    line_number: int | None = None
    source: str = "inline"

    def is_expired(self, now: datetime | None = None) -> bool:
        if self.expiry is None:
            return False
        current = now or datetime.now(timezone.utc)
        expiry = self.expiry
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        return expiry < current


@dataclass
class IgnoreRule:
    kind: str  # query | path | severity
    value: str
    source: str = "iacignore"
    metadata: dict[str, Any] = field(default_factory=dict)
