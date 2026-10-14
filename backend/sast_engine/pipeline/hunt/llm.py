"""Budget-enforcing LLM access for the hunt.

Every hunt LLM call — planner, investigator turns, and the independent
verifier (which reuses flow_verify / group-confirm) — goes through
`BudgetedLlm`, so the HuntBudget reservation/settlement brackets each call
no matter which stage makes it.
"""

from __future__ import annotations

import inspect
from typing import Any, Callable, Dict, Optional

from llm_client import call_llm
from pipeline.hunt.budget import HuntBudget


class HuntBudgetExceeded(RuntimeError):
    pass


class BudgetedLlm:
    def __init__(
        self,
        *,
        budget: HuntBudget,
        usage: Optional[Dict[str, Any]],
        provider: Optional[str],
        model: Optional[str],
        call_llm_fn: Callable[..., str] = call_llm,
    ) -> None:
        self.budget = budget
        self.usage = usage
        self.provider = provider
        self.model = model
        self._call = call_llm_fn
        self._passes_meta = _accepts_kwarg(call_llm_fn, "meta_out")
        # This wrapper's own spend. The engine gives each investigation its
        # own wrapper over the shared HuntBudget, so this is per-hypothesis.
        self.spent_usd = 0.0

    def __call__(
        self,
        system: str,
        user: str,
        max_tokens: int = 1500,
        temperature: float = 0.0,
        retries: int = 3,
        *,
        usage: Optional[Dict[str, Any]] = None,
        step: str = "hunt",
        provider: Optional[str] = None,
        model: Optional[str] = None,
        json_mode: bool = True,
        **_ignored: Any,
    ) -> str:
        """Same call shape as llm_client.call_llm, so it can be handed to
        flow_verify / group-confirm as their call_llm_fn. Raises
        HuntBudgetExceeded when the budget refuses the call."""
        prompt = f"{system}\n{user}"
        reservation = self.budget.reserve_llm(prompt, max_tokens)
        if reservation is None:
            raise HuntBudgetExceeded(self.budget.exhausted_reason or "hunt budget exhausted")
        meta: Dict[str, Any] = {}
        kwargs: Dict[str, Any] = {
            "max_tokens": max_tokens, "temperature": temperature,
            "usage": usage if usage is not None else self.usage,
            "step": step, "provider": provider or self.provider,
            "model": model or self.model, "json_mode": json_mode,
        }
        if self._passes_meta:
            kwargs["meta_out"] = meta
        try:
            text = self._call(system, user, **kwargs)
        except Exception:
            self.budget.release(reservation)
            raise
        self.spent_usd += self.budget.settle(reservation, meta=meta, prompt_text=prompt, response_text=text or "")
        return text or ""

    def for_investigation(self) -> "BudgetedLlm":
        """A sibling wrapper over the same budget with its own spend counter."""
        return BudgetedLlm(budget=self.budget, usage=self.usage, provider=self.provider,
                           model=self.model, call_llm_fn=self._call)


def _accepts_kwarg(fn: Callable[..., Any], name: str) -> bool:
    try:
        params = inspect.signature(fn).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(p.name == name or p.kind is inspect.Parameter.VAR_KEYWORD for p in params)
