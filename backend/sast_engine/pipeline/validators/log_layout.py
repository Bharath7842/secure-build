"""log_layout — does the appender this logger writes to neutralise line breaks?

A CWE-117 candidate that survives the call-boundary and value checks is only a
real forgery if the layout writes the text through. This validator resolves the
logger's category (``getLogger(Foo.class)`` -> the class, ``getLogger("audit")``
-> the name) to the appenders the repository's configuration gives it
(`logging_config`), and reads off what their layouts do to the part that
carries the text: the message, or the stack trace for a throwable argument.

* every appender neutralises that part -> negative proof ``log_layout_neutralises``
  naming the file and line;
* any appender prints it raw -> positive fact ``log_layout_raw``;
* no configuration in the repository, or a layout this cannot read -> a note
  (``log_layout_unknown``): recorded and counted, never settled. It asks for the
  deployed configuration, and it never lowers a finding that other evidence
  supports (a model true positive, a positive fact) or changes what the model is
  shown. (The spec calls this an evidence gap; a gap would demote every
  CWE-117 true positive of a repository whose layout is deployed elsewhere.)

The logging *library* is never a reason: `%m` in SLF4J/Log4j syntax is raw until a
layout says otherwise.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional, Set

from .. import logging_config as lc
from .. import output_sinks as sinks
from . import register
from ._logging import (
    CWE_117, LOG_RULE_IDS, LOG_RULE_PREFIXES, SOURCE_RE, arguments_text, call_source, local_sources,
    logger_call, method_text,
)
from .base import ValidatorResult, negative_proof, no_opinion, note, positive_fact

_NAME_RE = re.compile(r'getLogger\(\s*"([^"]+)"\s*\)')
_CLASS_RE = re.compile(r"getLogger\(\s*([\w.]+)\.class\s*\)")
_GETCLASS_RE = re.compile(r"getLogger\(\s*(?:this\.)?getClass\(\)\s*\)")


def category_of(facts: Dict[str, Any], graph: Any = None) -> Optional[str]:
    """The logger's name as the configuration sees it, or None when it cannot be told."""
    call = facts.get("call") or {}
    owner = (facts.get("enclosing") or {}).get("owner") or call.get("owner_fqn")
    for text in (call.get("receiver") or "", call.get("receiver_origin") or ""):
        m = _NAME_RE.search(text)
        if m:
            return m.group(1)
        m = _CLASS_RE.search(text)
        if m:
            name = m.group(1)
            if owner and (name == owner or owner.endswith("." + name) or owner == name):
                return owner
            if graph is not None and "." not in name and len(graph.types_by_simple.get(name, [])) == 1:
                return graph.types_by_simple[name][0]
            return name
        if _GETCLASS_RE.search(text):
            return owner
    if call.get("receiver") == "log" and not call.get("receiver_origin") and owner:
        return owner  # a Lombok @Slf4j field is named after its class
    return None


def relevant_parts(finding, facts, ctx, text: Optional[str]) -> Set[str]:
    """Which part of the record carries the candidate's text."""
    call = facts["call"]
    source = call_source(text, call)
    parts: Set[str] = set()
    if source is not None:
        arguments = arguments_text(source)
        if SOURCE_RE.search(arguments) or local_sources(method_text(text, facts), arguments):
            parts.add("message_crlf")
    if any(a.get("kind") == "throwable" for a in facts.get("args") or []):
        parts.add("throwable_crlf")
    return parts or {"message_crlf"}


@register("log_layout", 1, rule_ids=LOG_RULE_IDS, rule_prefixes=LOG_RULE_PREFIXES, cwes=(117,))
def log_layout(finding, facts, ctx) -> ValidatorResult:
    path = finding.get("file_path") or ""
    sink = logger_call(facts, path, ctx)
    if sink is None or sink.kind != sinks.LOGGER:
        return no_opinion()
    config = ctx.logging_config()
    if not config.found:
        return note(
            "log_layout_unknown",
            "No logging configuration in the repository: the deployed layout, and whether it encodes "
            "line breaks, is needed.",
            applies_to_cwe=CWE_117,
        )
    text = ctx.read_text(path) if path else None
    category = category_of(facts, getattr(ctx, "call_graph", None))
    resolution = config.resolve(category)
    parts = relevant_parts(finding, facts, ctx, text)
    if not resolution.layouts:
        return note(
            "log_layout_unknown",
            f"No appender in {config.summary()} resolves for logger {category or '(name not determinable)'}.",
            applies_to_cwe=CWE_117,
        )
    states = {part: resolution.part(part) for part in parts}
    label = {"message_crlf": "message", "throwable_crlf": "stack trace"}
    raw = [part for part, state in states.items() if state == lc.RAW]
    if raw:
        culprit = next(((p, a) for p, a in resolution.layouts if any(getattr(a.layout, r) == lc.RAW for r in raw)), None)
        where = culprit[1].layout.where if culprit else ""
        return positive_fact(
            "log_layout_raw",
            f"Appender {culprit[1].name if culprit else '?'} ({where}) writes the "
            f"{' and '.join(label[r] for r in raw)} without encoding CR/LF.",
            applies_to_cwe=CWE_117,
        )
    if all(state == lc.NEUTRALISED for state in states.values()):
        where = ", ".join(sorted({a.layout.where for _, a in resolution.layouts if a.layout.where}))[:120]
        return negative_proof(
            "log_layout_neutralises",
            f"Every appender for {category or 'this logger'} encodes CR/LF in the "
            f"{' and '.join(label[p] for p in sorted(parts))} ({where}).",
            applies_to_cwe=CWE_117,
        )
    return note(
        "log_layout_unknown",
        f"The layout for {category or 'this logger'} cannot be read ({config.summary()[:120]}).",
        applies_to_cwe=CWE_117,
    )
