"""log_call_boundary — a log-forging finding is about *this call's* arguments.

``java-log-injection-unsanitized-input`` finds ``log.x(`` and then looks up to
200 characters ahead, newlines included, for ``getMessage()`` or a request
accessor. That window leaves the call: ``log.info("done"); throw new
DBException(e.getMessage());`` matches although the log line is a constant.
The regex stays the candidate generator; this validator decides from the
parsed call.

* the call is not a logger (a JDK type that merely has an ``info`` method)
  -> not a log-forging sink;
* a named source is an argument of the call (directly, or through a local
  assigned from one) -> positive fact: the call really logs outside text;
* the call is a logger, its arguments hold no source, and the finding is the
  rule's own hit -> the source it blamed is in another statement: negative
  proof naming that line. A model finding is never dismissed on this ground,
  because its source can be any expression;
* a ``System.out`` call -> whether stdout ends up in a log file is not in the
  repository: evidence gap.

A throwable argument alone is not decided here: what text an exception can
carry is SAST-03-040's question.
"""

from __future__ import annotations

from .. import output_sinks as sinks
from . import register
from ._logging import (
    CWE_117, LOG_RULE_IDS, LOG_RULE_PREFIXES, SOURCE_RE, arguments_text, call_source,
    is_regex_candidate, local_sources, logger_call, method_text, next_source_line,
)
from .base import ValidatorResult, evidence_gap, negative_proof, no_opinion, positive_fact


@register("log_call_boundary", 1, rule_ids=LOG_RULE_IDS, rule_prefixes=LOG_RULE_PREFIXES, cwes=(117,))
def log_call_boundary(finding, facts, ctx) -> ValidatorResult:
    path = finding.get("file_path") or ""
    sink = logger_call(facts, path, ctx)
    if sink is None:
        return no_opinion()
    call = facts["call"]
    line = call.get("start_line")

    if sink.kind == sinks.OTHER:
        return negative_proof(
            "not_a_logger_call",
            f"The call at line {line} is {call.get('receiver') or 'a call'}.{call.get('callee')}() on "
            f"{sink.detail}, not a logger.",
            applies_to_cwe=CWE_117,
        )
    if sink.kind == sinks.PROCESS_STREAM:
        return evidence_gap(
            "whether System.out/err is captured into a log (container stdout redirection) "
            "is not in the repository",
            applies_to_cwe=CWE_117,
        )
    if sink.kind != sinks.LOGGER:
        return no_opinion()

    text = ctx.read_text(path) if path else None
    source = call_source(text, call)
    if source is None:
        return no_opinion()
    arguments = arguments_text(source)
    direct = SOURCE_RE.search(arguments)
    if direct:
        return positive_fact(
            "log_source_in_call",
            f"{direct.group().strip(' .(')}() is an argument of the log call at line {line}.",
            applies_to_cwe=CWE_117,
        )
    via = local_sources(method_text(text, facts), arguments)
    if via:
        return positive_fact(
            "log_source_via_local",
            f"The log call at line {line} logs {via[0]}, which is assigned from request or exception text.",
            applies_to_cwe=CWE_117,
        )
    if any(a.get("kind") == "throwable" for a in facts.get("args") or []):
        return no_opinion()  # the exception's text is SAST-03-040's question
    if not is_regex_candidate(finding):
        return no_opinion()
    where = next_source_line(text, call)
    named = f"{where[1]!r} at line {where[0]}, in a later statement" if where else "outside the call"
    return negative_proof(
        "log_source_outside_call",
        f"The log call at line {line} has no such argument; the source is {named}.",
        applies_to_cwe=CWE_117,
    )
