"""Small helpers every node uses to talk to the model through the gateway.

The engine never calls a model directly: it holds a `ModelGateway` (`app.dast.domain.interfaces`)
in `state["gateway"]` and asks it for a task. These helpers keep the call sites short and keep the
old "None means the model could not help" convention, so each node's existing fallback path (FIFO
crawl order, hard-coded login selectors, "unknown" login type) works unchanged.

The shared ethical-testing persona that used to live here as `SYSTEM_PROMPT` is now
`app/data/dast/prompts/_preamble.md`, prepended by the gateway to every task.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

HTML_SNIPPET_LENGTH = 800


def print_snippet(label: str, text: str, verbose: bool = True) -> None:
    """Print a truncated view of HTML/content being fed into a decision, for traceability."""
    if not verbose or not text:
        return
    snippet = text[:HTML_SNIPPET_LENGTH]
    suffix = "... [truncated]" if len(text) > HTML_SNIPPET_LENGTH else ""
    print(f"    [{label}]\n    {snippet}{suffix}")


def ask_json(
    gateway: Any,
    task: str,
    prompt: str,
    schema: Mapping[str, Any],
    *,
    system: str = "",
    max_tokens: int | None = None,
    temperature: float | None = None,
) -> Optional[dict]:
    """One gateway call. Returns the validated reply as a dict, or None when the gateway had to
    use its fallback (provider error or an unusable reply even after the repair attempt)."""
    reply = gateway.complete(task, system, prompt, schema, max_tokens=max_tokens, temperature=temperature)
    if reply.fallback_used:
        return None
    return dict(reply.data)
