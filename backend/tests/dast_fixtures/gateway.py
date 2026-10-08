"""A fake model gateway: scripted replies, recorded calls, simulated failures.

Implements the domain `ModelGateway` contract, so engine code that depends on the
interface can be tested without a model.

    gateway = FakeModelGateway()
    gateway.script("construct", {"tests": []})
    gateway.script_failure("rule", TimeoutError("model timed out"))
    gateway.script_malformed("narrate", "not json {")
    reply = gateway.complete("construct", "sys", "prompt", {"type": "object"})
    assert gateway.calls[0].task == "construct"
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Mapping

from app.dast.domain.interfaces import ModelReply


class ModelGatewayError(Exception):
    """Raised for a scripted failure that has no more specific exception."""


@dataclass(frozen=True)
class ModelCall:
    task: str
    system: str
    prompt: str
    reply_schema: Mapping[str, Any]
    max_tokens: int | None
    temperature: float | None
    thinking: bool = False


class FakeModelGateway:
    def __init__(self, *, strict: bool = True) -> None:
        self.calls: list[ModelCall] = []
        self._scripts: dict[str, deque[Any]] = defaultdict(deque)
        self._strict = strict

    # ---- scripting -----------------------------------------------------------------------

    def script(self, task: str, reply: Mapping[str, Any] | ModelReply, *, repeat: int = 1) -> None:
        """Queue `repeat` identical replies for `task`."""
        for _ in range(repeat):
            self._scripts[task].append(reply)

    def script_failure(self, task: str, error: BaseException | None = None) -> None:
        self._scripts[task].append(error or ModelGatewayError(f"scripted failure for {task}"))

    def script_malformed(self, task: str, text: str = "<<not valid json>>") -> None:
        """The reply the model returned could not be parsed; the call raises ValueError."""
        self._scripts[task].append(ValueError(f"malformed model reply: {text!r}"))

    # ---- the ModelGateway contract -------------------------------------------------------

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
        self.calls.append(ModelCall(task, system, prompt, reply_schema, max_tokens, temperature, thinking))
        queue = self._scripts[task]
        if not queue:
            if self._strict:
                raise AssertionError(f"unscripted model call for task {task!r}")
            return ModelReply(data={}, fallback_used=True)
        item = queue.popleft()
        if isinstance(item, BaseException):
            raise item
        if isinstance(item, ModelReply):
            return item
        return ModelReply(data=dict(item), input_tokens=len(prompt) // 4, output_tokens=len(str(item)) // 4)

    # ---- inspection ----------------------------------------------------------------------

    def calls_for(self, task: str) -> list[ModelCall]:
        return [c for c in self.calls if c.task == task]

    def pending(self, task: str) -> int:
        return len(self._scripts[task])
