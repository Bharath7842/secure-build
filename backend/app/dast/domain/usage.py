"""Token and cost accounting for model calls (DAST-02-050): pure aggregation.

Every gateway call becomes one `UsageRecord`; `UsageRecorder` collects them thread-safely and
`summary()` produces the dict stored at `Scan.metadata_json["usage_summary"]`. The shape extends
the SAST usage summary (`provider`, `model`, token totals, `cost_usd`, `call_count`, `by_step`)
rather than replacing it: `by_step` is keyed by gateway task, so the existing usage card renders
it, and `by_provider` is new.

Cost: local (ollama) calls cost nothing; hosted calls use a price table of USD per million
tokens, `{"provider/model": (input, output)}`, with a `"provider"` entry as that provider's
default. A model with no price is costed at zero and listed in `unpriced` so the gap is visible
instead of silently reading as free.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

# USD per million tokens (input, output). Override or extend through settings.
DEFAULT_PRICES: Mapping[str, tuple[float, float]] = {
    "ollama": (0.0, 0.0),
    "bedrock": (1.00, 5.00),  # Claude Haiku 4.5 class; the SAST engine uses the same figures
}


@dataclass(frozen=True)
class UsageRecord:
    task: str
    provider: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: float = 0.0
    fallback_used: bool = False
    repaired: bool = False
    attempts: int = 1
    estimated: bool = False  # tokens were estimated from text length, not reported by the provider


def price_for(provider: str, model: str, prices: Mapping[str, Any]) -> tuple[float, float] | None:
    for key in (f"{provider}/{model}", provider):
        if key in prices:
            value = prices[key]
            return float(value[0]), float(value[1])
    return None


def cost_of(record: UsageRecord, prices: Mapping[str, Any]) -> float:
    price = price_for(record.provider, record.model, prices)
    if price is None:
        return 0.0
    return record.input_tokens / 1_000_000 * price[0] + record.output_tokens / 1_000_000 * price[1]


def _bucket() -> dict[str, Any]:
    return {"calls": 0, "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0, "fallbacks": 0, "repairs": 0}


def _add(bucket: dict[str, Any], record: UsageRecord, cost: float) -> None:
    bucket["calls"] += 1
    bucket["input_tokens"] += record.input_tokens
    bucket["output_tokens"] += record.output_tokens
    bucket["cost_usd"] = round(bucket["cost_usd"] + cost, 6)
    bucket["fallbacks"] += int(record.fallback_used)
    bucket["repairs"] += int(record.repaired)


def summarize(records: Iterable[UsageRecord], prices: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Aggregate `records`. Totals always equal the sum of the per-task (and per-provider) buckets."""
    price_table = {**DEFAULT_PRICES, **(prices or {})}
    records = list(records)
    by_step: dict[str, dict[str, Any]] = {}
    by_provider: dict[str, dict[str, Any]] = {}
    total = _bucket()
    unpriced: set[str] = set()
    for record in records:
        cost = cost_of(record, price_table)
        if price_for(record.provider, record.model, price_table) is None:
            unpriced.add(f"{record.provider}/{record.model}")
        _add(by_step.setdefault(record.task, _bucket()), record, cost)
        _add(by_provider.setdefault(record.provider, _bucket()), record, cost)
        _add(total, record, cost)
    primary = max(by_provider, key=lambda p: by_provider[p]["calls"]) if by_provider else ""
    models = sorted({r.model for r in records if r.provider == primary})
    return {
        "provider": primary,
        "model": models[0] if len(models) == 1 else ", ".join(models),
        "input_tokens": total["input_tokens"],
        "output_tokens": total["output_tokens"],
        "total_tokens": total["input_tokens"] + total["output_tokens"],
        "cost_usd": round(total["cost_usd"], 6),
        "call_count": total["calls"],
        "fallback_count": total["fallbacks"],
        "repair_count": total["repairs"],
        "by_step": by_step,
        "by_provider": by_provider,
        "unpriced_models": sorted(unpriced),
        "estimated": any(r.estimated for r in records),
    }


def estimate_tokens(text: str) -> int:
    """Rough token count when a provider reports none (about four characters per token)."""
    return max(1, len(text or "") // 4) if text else 0


@dataclass
class UsageRecorder:
    """Thread-safe collector for one scan's model calls."""

    prices: Mapping[str, Any] = field(default_factory=dict)
    _records: list[UsageRecord] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def record(self, record: UsageRecord) -> None:
        with self._lock:
            self._records.append(record)

    @property
    def records(self) -> list[UsageRecord]:
        with self._lock:
            return list(self._records)

    def summary(self) -> dict[str, Any]:
        return summarize(self.records, self.prices)
