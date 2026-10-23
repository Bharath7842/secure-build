"""log_exception_provenance — can the logged exception carry outside text?

A log call that writes ``ex.getMessage()`` or the exception itself is only a
forging risk if some exception that can arrive at that catch has a message an
outsider can influence. `exception_provenance` works that out from the catch
types, the exceptions built in the try body, how the project builds its own
exception classes, and a small JDK table. Nothing here looks at the overload
(``log.error(msg, ex)`` or ``log.error(ex.getMessage())``) or at ``{}``
placeholders: neither is a defence.

* every candidate has fixed text and nothing else non-constant is logged ->
  negative proof ``exception_message_constrained``;
* some candidate may embed external text -> positive fact ``external_text_possible``;
* some candidate cannot be summarised -> evidence gap, naming it.
"""

from __future__ import annotations

from .. import exception_provenance as ep
from .. import output_sinks as sinks
from . import register
from ._logging import CWE_117, LOG_RULE_IDS, LOG_RULE_PREFIXES, logger_call
from .base import ValidatorResult, evidence_gap, negative_proof, no_opinion, positive_fact


@register("log_exception_provenance", 1, rule_ids=LOG_RULE_IDS, rule_prefixes=LOG_RULE_PREFIXES, cwes=(117,))
def log_exception_provenance(finding, facts, ctx) -> ValidatorResult:
    path = finding.get("file_path") or ""
    sink = logger_call(facts, path, ctx)
    if sink is None or sink.kind != sinks.LOGGER:
        return no_opinion()
    variables, other = ep.exception_vars(facts.get("args") or [])
    if not variables:
        return no_opinion()
    text = ctx.read_text(path) if path else None
    call = facts["call"]
    if not text or not call.get("start_line"):
        return no_opinion()
    summaries = ctx.exception_summaries()
    results = [summaries.summarise_at(path, text, int(call["start_line"]), int(call.get("start_col") or 0), v)
               for v in variables]
    domain = ep._worst(results)
    types = ", ".join(domain.types[:4]) or "the caught exception"
    line = call["start_line"]
    if domain.level == ep.EXTERNAL:
        return positive_fact(
            "external_text_possible",
            f"The exception logged at line {line} can be {types}; {domain.detail or 'its message can carry external text'}.",
            applies_to_cwe=CWE_117,
        )
    if domain.level == ep.UNKNOWN:
        return evidence_gap(
            f"exception_provenance_unknown: {domain.detail or types} (logged at line {line})",
            applies_to_cwe=CWE_117,
        )
    if other:
        return no_opinion()  # the exception is fixed text, but something else logged is not
    return negative_proof(
        "exception_message_constrained",
        f"The exception logged at line {line} can only be {types}: {domain.detail or 'fixed text'}.",
        applies_to_cwe=CWE_117,
    )
