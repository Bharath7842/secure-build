"""Thread-safe spend/effort ceilings for the hunt.

Concurrent investigators share one budget. Checking the running total
before each call is not enough — N workers can all see "$0.29 of $0.30" and
all proceed. Instead each LLM call *reserves* its worst-case cost (estimated
prompt + full max_tokens) under a lock before it is sent, and settles to the
real figure afterwards, so committed + in-flight spend can never exceed a
ceiling regardless of interleaving.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from llm_client import estimate_token_count, llm_cost_usd

DEFAULT_MAX_USD = 0.60
DEFAULT_MAX_TOKENS = 2_000_000
DEFAULT_MAX_WALL_SECONDS = 1_800.0
DEFAULT_MAX_LLM_CALLS = 400
DEFAULT_MAX_RG_CALLS = 2_000
# Share of the scan-wide cost cutoff left when the hunt starts that the hunt
# may spend, so it can never starve the stages after it.
DEFAULT_CUTOFF_SHARE = 0.30


@dataclass(frozen=True)
class BudgetLimits:
    max_usd: Optional[float] = DEFAULT_MAX_USD
    max_tokens: Optional[int] = DEFAULT_MAX_TOKENS
    max_wall_seconds: Optional[float] = DEFAULT_MAX_WALL_SECONDS
    max_llm_calls: Optional[int] = DEFAULT_MAX_LLM_CALLS
    max_rg_calls: Optional[int] = DEFAULT_MAX_RG_CALLS

    @classmethod
    def for_scan(
        cls,
        usage: Optional[Dict[str, Any]],
        *,
        max_usd: Optional[float] = None,
        **overrides: Any,
    ) -> "BudgetLimits":
        """Default the USD ceiling to DEFAULT_CUTOFF_SHARE of whatever the
        scan's cost cutoff has left; an explicit `max_usd` wins."""
        if max_usd is None:
            cutoff = (usage or {}).get("cost_cutoff_usd")
            if cutoff is not None:
                spent = float((usage or {}).get("cost_usd") or 0.0)
                max_usd = max(0.0, (float(cutoff) - spent) * DEFAULT_CUTOFF_SHARE)
            else:
                max_usd = None  # no scan-wide cutoff (e.g. free local model)
        return cls(max_usd=max_usd, **overrides)


@dataclass
class Reservation:
    usd: float
    tokens: int
    settled: bool = False


class HuntBudget:
    def __init__(
        self,
        limits: BudgetLimits,
        *,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.limits = limits
        self.provider = provider or "bedrock"
        self.model = model
        self._clock = clock
        self._started = clock()
        self._lock = threading.Lock()
        self.spent_usd = 0.0
        self.spent_tokens = 0
        self.reserved_usd = 0.0
        self.reserved_tokens = 0
        self.llm_calls = 0
        self.rg_calls = 0
        self.refusals: Dict[str, int] = {}
        self.exhausted_reason: Optional[str] = None

    # -- helpers -----------------------------------------------------------

    def _refuse(self, reason: str) -> None:
        self.refusals[reason] = self.refusals.get(reason, 0) + 1
        if self.exhausted_reason is None:
            self.exhausted_reason = reason

    def _wall_exceeded(self) -> bool:
        limit = self.limits.max_wall_seconds
        return limit is not None and (self._clock() - self._started) >= limit

    def elapsed_seconds(self) -> float:
        return self._clock() - self._started

    # -- LLM calls ---------------------------------------------------------

    def reserve_llm(self, prompt_text: str, max_output_tokens: int) -> Optional[Reservation]:
        """Reserve the worst case for one call; None means refused (the
        reason is in `exhausted_reason`)."""
        est_input = estimate_token_count(prompt_text)
        worst_tokens = est_input + int(max_output_tokens)
        worst_usd = llm_cost_usd(est_input, int(max_output_tokens), self.provider, self.model)
        with self._lock:
            if self._wall_exceeded():
                self._refuse("wall_clock")
                return None
            if self.limits.max_llm_calls is not None and self.llm_calls >= self.limits.max_llm_calls:
                self._refuse("llm_calls")
                return None
            if (
                self.limits.max_tokens is not None
                and self.spent_tokens + self.reserved_tokens + worst_tokens > self.limits.max_tokens
            ):
                self._refuse("tokens")
                return None
            if (
                self.limits.max_usd is not None
                and self.spent_usd + self.reserved_usd + worst_usd > self.limits.max_usd + 1e-12
            ):
                self._refuse("usd")
                return None
            self.llm_calls += 1
            self.reserved_usd += worst_usd
            self.reserved_tokens += worst_tokens
            return Reservation(usd=worst_usd, tokens=worst_tokens)

    def settle(
        self,
        reservation: Reservation,
        *,
        meta: Optional[Dict[str, Any]] = None,
        prompt_text: str = "",
        response_text: str = "",
    ) -> float:
        """Replace the reservation with the call's real cost (returned, in
        USD). `meta` is the `meta_out` call_llm filled in; without it (e.g. a
        test double) the tokens are estimated from the texts."""
        meta = meta or {}
        if meta.get("input_tokens") is not None and meta.get("output_tokens") is not None:
            inp, out = int(meta["input_tokens"]), int(meta["output_tokens"])
        else:
            inp, out = estimate_token_count(prompt_text), estimate_token_count(response_text)
        usd = llm_cost_usd(inp, out, meta.get("provider") or self.provider, meta.get("model") or self.model)
        with self._lock:
            if reservation.settled:
                return 0.0
            reservation.settled = True
            self.reserved_usd -= reservation.usd
            self.reserved_tokens -= reservation.tokens
            self.spent_usd += usd
            self.spent_tokens += inp + out
        return usd

    def remaining_usd(self) -> Optional[float]:
        """USD left after committed and in-flight spend; None when uncapped."""
        if self.limits.max_usd is None:
            return None
        with self._lock:
            return max(0.0, self.limits.max_usd - self.spent_usd - self.reserved_usd)

    def release(self, reservation: Reservation) -> None:
        """The call raised before the provider billed anything we can see."""
        with self._lock:
            if reservation.settled:
                return
            reservation.settled = True
            self.reserved_usd -= reservation.usd
            self.reserved_tokens -= reservation.tokens

    # -- ripgrep calls -----------------------------------------------------

    def reserve_rg(self) -> bool:
        with self._lock:
            if self._wall_exceeded():
                self._refuse("wall_clock")
                return False
            if self.limits.max_rg_calls is not None and self.rg_calls >= self.limits.max_rg_calls:
                self._refuse("rg_calls")
                return False
            self.rg_calls += 1
            return True

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "spent_usd": round(self.spent_usd, 6),
                "spent_tokens": self.spent_tokens,
                "llm_calls": self.llm_calls,
                "rg_calls": self.rg_calls,
                "elapsed_seconds": round(self.elapsed_seconds(), 2),
                "limits": {
                    "max_usd": self.limits.max_usd,
                    "max_tokens": self.limits.max_tokens,
                    "max_wall_seconds": self.limits.max_wall_seconds,
                    "max_llm_calls": self.limits.max_llm_calls,
                    "max_rg_calls": self.limits.max_rg_calls,
                },
                "refusals": dict(self.refusals),
                "exhausted_reason": self.exhausted_reason,
            }
