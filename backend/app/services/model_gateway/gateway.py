"""The model gateway core (DAST-02-010): the only component that calls a model.

    complete(task, system, prompt, reply_schema, max_tokens=, temperature=) -> ModelReply

* **Routing.** The task picks provider and model from the routing table (the scan's snapshotted
  `model_routing`, see `Settings.dast_model_routing`). An unknown task raises `UnknownTaskError`
  listing the known ones; that is a programming error, not a runtime condition.
* **Validation.** The reply must parse as JSON and satisfy `reply_schema`. A malformed reply
  gets exactly one repair attempt (the problems are quoted back to the model); if that also
  fails, the task's fallback is returned.
* **Fallback.** Provider errors (timeout, unavailable, auth, missing configuration) never fail
  the scan: the call is logged, and the task's deterministic fallback comes back with
  `fallback_used=True` and the reason. A fallback is registered per task by the caller
  (`register_fallback`); with none registered the fallback is an empty mapping.
* **Accounting.** Every call, including fallbacks, becomes one `UsageRecord`.
* **No verdicts.** What comes back is advice; the domain's guardrail decides what is recorded.

The gateway writes nothing about credentials: error text is passed through `redact_text` with
the configured secret values before it is logged or returned in `reason`.
"""

from __future__ import annotations

import copy
import json
import threading
import time
from typing import Any, Callable, Iterable, Iterator, Mapping

from app.dast.domain.interfaces import AdapterResponse, ModelAdapter, ModelReply
from app.dast.domain.model_errors import ModelConfigurationError, ModelError, UnknownTaskError
from app.dast.domain.redaction import redact_text
from app.dast.domain.schema import extract_json, validate_reply
from app.dast.domain.usage import DEFAULT_PRICES, UsageRecord, UsageRecorder, cost_of, estimate_tokens

from .prompts import PromptLibrary

AdapterFactory = Callable[[str, str], ModelAdapter]
Fallback = Mapping[str, Any] | Callable[[], Mapping[str, Any]]


class ModelGatewayImpl:
    def __init__(
        self,
        routing: Mapping[str, tuple[str, str]],
        adapter_factory: AdapterFactory,
        *,
        prompts: PromptLibrary | None = None,
        usage: UsageRecorder | None = None,
        secrets: Callable[[], Iterable[str]] | None = None,
        log: Callable[[str], None] | None = None,
        default_max_tokens: int | None = None,
    ) -> None:
        self._routing = {task: (str(p), str(m)) for task, (p, m) in routing.items()}
        self._adapter_factory = adapter_factory
        self._adapters: dict[tuple[str, str], ModelAdapter] = {}
        self._adapter_lock = threading.Lock()  # calls may come from several worker threads
        self._fallbacks: dict[str, Fallback] = {}
        self._prompts = prompts
        self.usage = usage or UsageRecorder()
        self._secrets = secrets or (lambda: ())
        self._log = log or print
        self._default_max_tokens = default_max_tokens

    # ---- configuration ------------------------------------------------------------------------

    @property
    def tasks(self) -> tuple[str, ...]:
        return tuple(self._routing)

    def route(self, task: str) -> tuple[str, str]:
        try:
            return self._routing[task]
        except KeyError:
            raise UnknownTaskError(
                f"unknown model task {task!r}; known tasks: {', '.join(sorted(self._routing))}"
            ) from None

    def register_fallback(self, task: str, fallback: Fallback) -> None:
        """The deterministic result used when `task` cannot get a usable model reply."""
        self.route(task)  # reject a fallback for a task that does not exist
        self._fallbacks[task] = fallback

    def _fallback_data(self, task: str) -> dict[str, Any]:
        fallback = self._fallbacks.get(task)
        value = fallback() if callable(fallback) else fallback
        return copy.deepcopy(dict(value)) if value is not None else {}

    def _adapter(self, provider: str, model: str) -> ModelAdapter:
        key = (provider, model)
        with self._adapter_lock:
            if key not in self._adapters:
                self._adapters[key] = self._adapter_factory(provider, model)
            return self._adapters[key]

    def check_configuration(self) -> list[str]:
        """Problems that would make a task's provider unusable (a missing API key, no region).
        Empty means every routed provider can at least be constructed and has what it needs."""
        problems: list[str] = []
        for task, (provider, model) in self._routing.items():
            try:
                adapter = self._adapter(provider, model)
                probe = getattr(adapter, "check_configuration", None)
                if probe:
                    probe()
            except ModelConfigurationError as exc:
                problems.append(f"{task} ({provider}): {redact_text(str(exc), self._secrets())}")
        return problems

    # ---- the call -----------------------------------------------------------------------------

    def complete(
        self,
        task: str,
        system: str,
        prompt: str,
        reply_schema: Mapping[str, Any],
        *,
        max_tokens: int | None = None,
        temperature: float | None = None,
        thinking: bool = False,
    ) -> ModelReply:
        provider, model = self.route(task)
        max_tokens = max_tokens or self._default_max_tokens
        full_system = self._prompts.compose(task, system) if self._prompts else system
        started = time.perf_counter()
        input_tokens = output_tokens = attempts = 0
        estimated = False
        repaired = False
        reason = ""
        data: Any = None
        ok = False

        try:
            adapter = self._adapter(provider, model)
            next_prompt = prompt
            for attempt in (1, 2):  # the original call, then at most one repair
                attempts = attempt
                response: AdapterResponse = adapter.call(full_system, next_prompt, reply_schema, max_tokens, temperature, thinking=thinking)
                input_tokens += response.input_tokens
                output_tokens += response.output_tokens
                estimated = estimated or response.estimated
                problems: list[str] = []
                try:
                    candidate = response.data if response.data is not None else extract_json(response.text)
                    problems = validate_reply(candidate, reply_schema)
                except ValueError as exc:
                    candidate, problems = None, [str(exc)]
                if not problems:
                    data, ok, repaired = candidate, True, attempt == 2
                    break
                reason = "reply did not match the expected shape: " + "; ".join(problems[:3])
                next_prompt = self._repair_prompt(prompt, response.text, problems, reply_schema)
        except ModelError as exc:
            reason = f"{type(exc).__name__}: {redact_text(str(exc), self._secrets())}"
        except Exception as exc:  # noqa: BLE001 - an adapter bug must not fail the scan
            reason = f"unexpected {type(exc).__name__}: {redact_text(str(exc), self._secrets())}"

        latency_ms = (time.perf_counter() - started) * 1000
        if not ok:
            self._log(f"    (model task '{task}' used its fallback: {reason})")
            data = self._fallback_data(task)
        if not input_tokens and not output_tokens and ok:
            input_tokens, output_tokens, estimated = estimate_tokens(full_system + prompt), estimate_tokens(json.dumps(data)), True

        record = UsageRecord(
            task=task, provider=provider, model=model, input_tokens=input_tokens, output_tokens=output_tokens,
            latency_ms=latency_ms, fallback_used=not ok, repaired=repaired, attempts=max(attempts, 1), estimated=estimated,
        )
        self.usage.record(record)
        return ModelReply(
            data=data if isinstance(data, Mapping) else {"value": data},
            fallback_used=not ok,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost_of(record, {**DEFAULT_PRICES, **(self.usage.prices or {})}),
            provider=provider,
            model=model,
            latency_ms=latency_ms,
            repaired=repaired,
            reason="" if ok else reason,
        )

    @staticmethod
    def _repair_prompt(prompt: str, previous: str, problems: list[str], schema: Mapping[str, Any]) -> str:
        shown = (previous or "")[:1500]
        return (
            f"{prompt}\n\nYour previous reply could not be used.\n"
            f"Problems: {'; '.join(problems[:5])}\n"
            f"Previous reply:\n{shown}\n\n"
            f"Reply again with ONLY one JSON value matching this schema, no commentary:\n"
            f"{json.dumps(schema, sort_keys=True)}"
        )

    # ---- streaming (narration) ----------------------------------------------------------------

    def stream(
        self,
        task: str,
        system: str,
        prompt: str,
        *,
        max_tokens: int | None = None,
        temperature: float | None = None,
        thinking: bool = False,
    ) -> Iterator[tuple[str, str]]:
        """Yield `("thinking"|"response", text)` then `("done", "")`, or `("error", message)`.

        Only adapters that can stream (the local one) support this; for the rest the whole reply
        arrives as one `response` event. The narration view uses it for live reasoning tokens.
        `thinking=True` is honoured by adapters that support extended thinking even without a
        streaming path (e.g. Bedrock): no `("thinking", ...)` event comes out of this fallback
        call, but the adapter still writes it to the scan log via its own side channel."""
        provider, model = self.route(task)
        full_system = self._prompts.compose(task, system) if self._prompts else system
        started = time.perf_counter()
        parts: list[str] = []
        try:
            adapter = self._adapter(provider, model)
            streamer = getattr(adapter, "stream", None)
            if streamer is None:
                response = adapter.call(full_system, prompt, None, max_tokens or self._default_max_tokens, temperature, thinking=thinking)
                parts.append(response.text)
                yield "response", response.text
            else:
                for kind, text, _chunk in streamer(full_system, prompt, max_tokens or self._default_max_tokens, temperature):
                    if kind == "response":
                        parts.append(text)
                    yield kind, text
        except Exception as exc:  # noqa: BLE001
            message = redact_text(str(exc) or type(exc).__name__, self._secrets())
            self._log(f"    (model task '{task}' streaming failed: {message})")
            self.usage.record(UsageRecord(task, provider, model, fallback_used=True, latency_ms=(time.perf_counter() - started) * 1000))
            yield "error", message
            return
        text = "".join(parts)
        self.usage.record(
            UsageRecord(
                task, provider, model, estimate_tokens(full_system + prompt), estimate_tokens(text),
                latency_ms=(time.perf_counter() - started) * 1000, estimated=True,
            )
        )
        yield ("done", "") if text else ("error", "Empty response from model")
