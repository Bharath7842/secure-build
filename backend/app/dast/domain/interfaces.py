"""Domain contracts implemented by infrastructure (see architecture.md, "Interface Contracts").

Protocols only: the engine and domain depend on these, concrete classes live in
infrastructure and the mock engine, and tests substitute fakes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable

from .entities import Check, Finding, Identity, ResponseSnapshot, RulePack


@dataclass(frozen=True)
class RequestSpec:
    """A request the engine wants sent. Never carries credentials in `url`."""

    method: str
    url: str
    identity_id: str | None = None
    identity_label: str | None = None  # attributes audit rows; falls back to identity_id
    headers: Mapping[str, str] | None = None
    body: Any = None
    check_id: str | None = None
    intent: str | None = None  # e.g. policy.INTROSPECTION_INTENT; verified against the body by the guard
    max_body_bytes: int | None = None  # keep more of the response than the default cap (schema documents)


@dataclass(frozen=True)
class GuardDecision:
    """Result of the safety guard: allow with a response, or deny with a reason."""

    allowed: bool
    response: ResponseSnapshot | None = None
    deny_reason: str | None = None  # off_scope | method_not_permitted | cancelled (see policy.DENY_REASONS)
    audit_seq: int | None = None
    # Allowed but never completed (timeout, connection failure). `response` is None then.
    # On a denial that stopped a redirect, `response` is the redirecting 3xx.
    error: str | None = None
    error_detail: str = ""  # the failure's message, with credentials redacted; for classification


@dataclass(frozen=True)
class ModelReply:
    """Validated model output, or a deterministic fallback when `fallback_used`."""

    data: Mapping[str, Any]
    fallback_used: bool = False
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    provider: str = ""
    model: str = ""
    latency_ms: float = 0.0
    repaired: bool = False  # the first reply was invalid and a repair attempt produced this one
    reason: str = ""  # why the fallback was used, when it was


@dataclass(frozen=True)
class AdapterResponse:
    """What a provider adapter returns: raw text (or already-parsed data) plus token counts."""

    text: str = ""
    data: Any = None
    input_tokens: int = 0
    output_tokens: int = 0
    estimated: bool = False  # token counts were estimated, not reported


@runtime_checkable
class RequestExecutor(Protocol):
    """Sends a request to the target. The only path to it is through the safety guard."""

    def execute(self, request: RequestSpec) -> GuardDecision: ...


@runtime_checkable
class BrowserDriver(Protocol):
    """Headless browser used for the crawl; its outgoing requests route through the guard."""

    def open(self, url: str, identity_id: str | None = None) -> None: ...

    def close(self) -> None: ...


@runtime_checkable
class ModelGateway(Protocol):
    """The only component that calls a model. Tasks: fingerprint, crawl_plan,
    login_selectors, normalize_endpoints, plan, construct, rule, narrate."""

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
    ) -> ModelReply: ...


@runtime_checkable
class ModelAdapter(Protocol):
    """One provider behind the gateway. SDKs are imported lazily inside `call`. Raises the
    `model_errors` hierarchy; never returns a verdict, only text for the gateway to validate."""

    provider: str
    supports_tool_choice: bool

    def call(
        self,
        system: str,
        prompt: str,
        schema: Mapping[str, Any] | None,
        max_tokens: int | None,
        temperature: float | None,
        thinking: bool = False,
    ) -> AdapterResponse: ...


@runtime_checkable
class CheckCatalog(Protocol):
    def packs(self) -> Sequence[RulePack]: ...

    def checks(self, pack_id: str | None = None) -> Sequence[Check]: ...

    def get(self, check_id: str) -> Check | None: ...


@runtime_checkable
class FindingStore(Protocol):
    """Persists findings incrementally while the scan runs."""

    def write(self, scan_id: str, findings: Sequence[Finding]) -> None: ...


@runtime_checkable
class CredentialHolder(Protocol):
    """Memory-only credential store for one scan; clears everything at scan end."""

    def store(self, identity: Identity, secret: Mapping[str, str]) -> None: ...

    def read(self, identity_id: str) -> Mapping[str, str] | None: ...

    def clear(self) -> None: ...
