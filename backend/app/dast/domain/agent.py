"""Bounded planning and adaptive-test vocabulary. No I/O or model dependencies."""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from .entities import Endpoint

MAX_HISTORY_TURNS = 20
MAX_PLAN_ITEMS = 500


def target_key(endpoint: Endpoint) -> str:
    return f"{endpoint.method.upper()} {endpoint.path_template}"


@dataclass(frozen=True)
class Hypothesis:
    id: str
    target_key: str
    owasp: str
    check_ids: tuple[str, ...]
    rationale: str = ""
    priority: int = 1
    max_turns: int = 4


@dataclass(frozen=True)
class Plan:
    hypotheses: tuple[Hypothesis, ...] = ()
    dropped: Mapping[str, int] = field(default_factory=dict)

    def for_target(self, endpoint: Endpoint) -> tuple[Hypothesis, ...]:
        return tuple(h for h in self.hypotheses if h.target_key == target_key(endpoint))

    def authorization_priority(self) -> list[str]:
        return list(dict.fromkeys(h.target_key for h in self.hypotheses if h.owasp == "A01:2021"))


def parse_plan(reply: Mapping[str, Any] | None, endpoints: Sequence[Endpoint], checks: Mapping[str, Any], *, max_hypotheses: int) -> Plan:
    """Accept only known targets/checks; bound even malformed model output, then rank and cap."""
    dropped = dict(malformed=0, unknown_endpoint=0, unknown_check=0, duplicate=0, over_cap=0)
    raw = reply.get("hypotheses", []) if isinstance(reply, Mapping) else []
    if not isinstance(raw, list):
        return Plan(dropped={**dropped, "malformed": 1})
    known = {target_key(e) for e in endpoints}
    hypotheses = []
    seen = set()
    dropped["over_cap"] = max(0, len(raw) - MAX_PLAN_ITEMS)
    for item in raw[:MAX_PLAN_ITEMS]:
        if not isinstance(item, Mapping):
            dropped["malformed"] += 1
            continue
        key = item.get("target_key")
        ids = item.get("check_ids")
        tag = item.get("owasp", "")
        priority, turns = item.get("priority", 1), item.get("max_turns", 4)
        if (not isinstance(key, str) or not isinstance(ids, list) or not ids
                or not all(isinstance(c, str) for c in ids)
                or not isinstance(tag, str) or not re.fullmatch(r"A(?:0[1-9]|10):2021", tag)
                or type(priority) is not int or type(turns) is not int or turns < 1):
            dropped["malformed"] += 1
            continue
        if key not in known:
            dropped["unknown_endpoint"] += 1
            continue
        if any(c not in checks for c in ids):
            dropped["unknown_check"] += 1
            continue
        ids = tuple(dict.fromkeys(ids))
        signature = (key, tag, tuple(sorted(ids)))
        if signature in seen:
            dropped["duplicate"] += 1
            continue
        seen.add(signature)
        # Use our own ids: duplicate/untrusted model ids must not share a budget bucket.
        hypotheses.append(Hypothesis(f"h{len(hypotheses) + 1}", key, tag, ids,
                                     str(item.get("rationale") or "")[:600], max(0, priority), min(turns, MAX_HISTORY_TURNS)))
    hypotheses.sort(key=lambda h: h.priority)
    cap = max(0, min(max_hypotheses, MAX_PLAN_ITEMS))
    dropped["over_cap"] += max(0, len(hypotheses) - cap)
    return Plan(tuple(hypotheses[:cap]), dropped)


@dataclass(frozen=True)
class Turn:
    check_id: str = ""
    status: int | None = None
    length_delta: int = 0
    elapsed_ms: float = 0.0
    signals: tuple[str, ...] = ()
    proven: bool = False


@dataclass
class History:
    hypothesis: Hypothesis
    turns: list[Turn] = field(default_factory=list)
    attempts: int = 0
    model_stopped: bool = False
    cancelled: bool = False
    proven: bool = False

    def append(self, turn: Turn) -> None:
        self.turns.append(turn)
        del self.turns[:-MAX_HISTORY_TURNS]
        self.proven = self.proven or turn.proven


class AgentBudget:
    """Reserve a model turn atomically, shared by all endpoint workers in one scan."""

    def __init__(self, max_turns: int = 60, per_hypothesis: int = 4):
        self.max_turns = max(0, int(max_turns))
        self.per_hypothesis = max(0, min(int(per_hypothesis), MAX_HISTORY_TURNS))
        self._used = 0
        self._by_hypothesis: dict[str, int] = {}
        self._lock = threading.Lock()

    def remaining(self) -> int:
        with self._lock:
            return self.max_turns - self._used

    def used_by(self, hypothesis: Hypothesis) -> int:
        with self._lock:
            return self._by_hypothesis.get(hypothesis.id, 0)

    def reserve(self, hypothesis: Hypothesis) -> bool:
        with self._lock:
            used = self._by_hypothesis.get(hypothesis.id, 0)
            if self._used >= self.max_turns or used >= min(hypothesis.max_turns, self.per_hypothesis):
                return False
            self._used += 1
            self._by_hypothesis[hypothesis.id] = used + 1
            return True


def should_stop(history: History, hypothesis: Hypothesis, budget: AgentBudget) -> bool:
    return (history.proven or history.model_stopped or history.cancelled
            or history.attempts >= min(hypothesis.max_turns, budget.per_hypothesis)
            or budget.used_by(hypothesis) >= min(hypothesis.max_turns, budget.per_hypothesis)
            or budget.remaining() <= 0)


def agent_limits(total: int, per_hypothesis: int, routing: Mapping[str, Sequence[str]]) -> tuple[int, int]:
    """Small/unsized Ollama construct models get fewer adaptive calls; hosted routes keep the cap."""
    route = routing.get("construct", ())
    if route and route[0] == "ollama":
        size = re.search(r"(\d+(?:\.\d+)?)b(?:\b|_)", route[1] if len(route) > 1 else "", re.I)
        if size is None or float(size.group(1)) <= 32:
            return min(total, 20), min(per_hypothesis, 2)
    return total, per_hypothesis
