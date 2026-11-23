"""LLM usage across scans for Monitor -> LLM observability.

Built only from what every scan already stores (`Scan.metadata_json
["usage_summary"]`, written by SAST and DAST alike).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Project, Scan

RANGES: dict[str, timedelta] = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
    "90d": timedelta(days=90),
}
DEFAULT_RANGE = "7d"
TOP_SCANS = 10


def range_bounds(range_key: str, now: datetime | None = None) -> tuple[datetime, datetime, str]:
    """(from, to, bucket granularity) for one of RANGES."""
    now = now or datetime.now(timezone.utc)
    span = RANGES.get(range_key) or RANGES[DEFAULT_RANGE]
    return now - span, now, "hour" if span <= timedelta(hours=24) else "day"


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _bucket_start(dt: datetime, granularity: str) -> datetime:
    dt = _aware(dt).astimezone(timezone.utc)
    if granularity == "hour":
        return dt.replace(minute=0, second=0, microsecond=0)
    return dt.replace(hour=0, minute=0, second=0, microsecond=0)


def _buckets(start: datetime, end: datetime, granularity: str) -> list[datetime]:
    step = timedelta(hours=1) if granularity == "hour" else timedelta(days=1)
    out, cursor = [], _bucket_start(start, granularity)
    while cursor <= end:
        out.append(cursor)
        cursor += step
    return out


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _float(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _empty_totals() -> dict[str, Any]:
    return {
        "scans": 0,
        "scans_with_llm": 0,
        "scans_without_usage": 0,
        "llm_calls": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "cost_usd": 0.0,
        "result_cache_hits": 0,
        "result_cache_saved_tokens": 0,
        "estimated_scans": 0,
        "fallback_scans": 0,
        "budget_exhausted_scans": 0,
        "failed_scans": 0,
    }


def collect(db: Session, range_key: str = DEFAULT_RANGE, *, now: datetime | None = None) -> dict[str, Any]:
    """Aggregate every scan created in the range (all users: the page is admin-only)."""
    start, end, granularity = range_bounds(range_key, now)
    rows = db.execute(
        select(Scan, Project.name)
        .join(Project, Project.id == Scan.project_id, isouter=True)
        .where(Scan.created_at >= start)
        .order_by(Scan.created_at)
    ).all()

    totals = _empty_totals()
    series = {b: {"scans": 0, "calls": 0, "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}
              for b in _buckets(start, end, granularity)}
    by_type: dict[str, dict[str, Any]] = {}
    by_model: dict[tuple[str, str], dict[str, Any]] = {}
    by_step: dict[str, dict[str, Any]] = {}
    scans: list[dict[str, Any]] = []

    for scan, project_name in rows:
        totals["scans"] += 1
        if scan.status == "failed":
            totals["failed_scans"] += 1
        kind = (scan.scan_type or "sast").lower()
        type_bucket = by_type.setdefault(kind, {"scan_type": kind, "scans": 0, "calls": 0, "total_tokens": 0, "cost_usd": 0.0})
        type_bucket["scans"] += 1
        bucket_key = _bucket_start(scan.created_at, granularity)
        point = series.get(bucket_key)
        if point is not None:
            point["scans"] += 1

        usage = (scan.metadata_json or {}).get("usage_summary")
        if not isinstance(usage, dict):
            totals["scans_without_usage"] += 1
            continue
        calls = _int(usage.get("call_count"))
        inp, out = _int(usage.get("input_tokens")), _int(usage.get("output_tokens"))
        cost = _float(usage.get("cost_usd"))
        cache_hits = _int(usage.get("result_cache_hits"))
        if calls or cache_hits:
            totals["scans_with_llm"] += 1
        totals["llm_calls"] += calls
        totals["input_tokens"] += inp
        totals["output_tokens"] += out
        totals["total_tokens"] += inp + out
        totals["cost_usd"] += cost
        totals["result_cache_hits"] += cache_hits
        totals["result_cache_saved_tokens"] += _int(usage.get("result_cache_saved_tokens"))
        totals["estimated_scans"] += 1 if usage.get("estimated") else 0
        totals["fallback_scans"] += 1 if (usage.get("fallback_switched") or _int(usage.get("fallback_count"))) else 0
        totals["budget_exhausted_scans"] += 1 if usage.get("budget_exhausted") else 0

        type_bucket["calls"] += calls
        type_bucket["total_tokens"] += inp + out
        type_bucket["cost_usd"] += cost
        if point is not None:
            point["calls"] += calls
            point["input_tokens"] += inp
            point["output_tokens"] += out
            point["cost_usd"] += cost

        if calls:
            provider = str(usage.get("provider") or scan.llm_provider or "unknown")
            model = str(usage.get("model") or scan.llm_model or "")
            model_bucket = by_model.setdefault((provider, model), {
                "provider": provider, "model": model, "scans": 0, "calls": 0,
                "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0,
            })
            model_bucket["scans"] += 1
            model_bucket["calls"] += calls
            model_bucket["input_tokens"] += inp
            model_bucket["output_tokens"] += out
            model_bucket["cost_usd"] += cost

        for step, data in (usage.get("by_step") or {}).items():
            if not isinstance(data, dict):
                continue
            step_bucket = by_step.setdefault(str(step), {
                "step": str(step), "scan_type": kind, "calls": 0, "input_tokens": 0,
                "output_tokens": 0, "result_cache_hits": 0, "truncated": 0,
            })
            step_bucket["calls"] += _int(data.get("calls"))
            step_bucket["input_tokens"] += _int(data.get("input_tokens"))
            step_bucket["output_tokens"] += _int(data.get("output_tokens"))
            step_bucket["result_cache_hits"] += _int(data.get("result_cache_hits"))
            step_bucket["truncated"] += _int(data.get("truncated"))

        if calls or cost:
            scans.append({
                "scan_id": scan.id,
                "project_id": scan.project_id,
                "project_name": project_name,
                "scan_type": kind,
                "version": scan.version,
                "status": scan.status,
                "created_at": _aware(scan.created_at).isoformat(),
                "provider": usage.get("provider") or scan.llm_provider,
                "model": usage.get("model") or scan.llm_model,
                "calls": calls,
                "total_tokens": inp + out,
                "cost_usd": round(cost, 6),
                "result_cache_hits": cache_hits,
            })

    totals["cost_usd"] = round(totals["cost_usd"], 6)
    sent = totals["llm_calls"] + totals["result_cache_hits"]
    totals["result_cache_hit_rate"] = round(totals["result_cache_hits"] / sent, 4) if sent else 0.0
    scans.sort(key=lambda s: (s["cost_usd"], s["total_tokens"]), reverse=True)
    return {
        "range": range_key if range_key in RANGES else DEFAULT_RANGE,
        "from": start.isoformat(),
        "to": end.isoformat(),
        "granularity": granularity,
        "totals": totals,
        "series": [
            {"bucket": b.isoformat(), **{k: (round(v, 6) if isinstance(v, float) else v) for k, v in p.items()}}
            for b, p in series.items()
        ],
        "by_type": sorted(
            ({**t, "cost_usd": round(t["cost_usd"], 6)} for t in by_type.values()),
            key=lambda t: t["scans"], reverse=True,
        ),
        "by_model": sorted(
            ({**m, "cost_usd": round(m["cost_usd"], 6)} for m in by_model.values()),
            key=lambda m: (m["cost_usd"], m["calls"]), reverse=True,
        ),
        "by_step": sorted(by_step.values(), key=lambda s: s["input_tokens"] + s["output_tokens"], reverse=True),
        "top_scans": scans[:TOP_SCANS],
    }
