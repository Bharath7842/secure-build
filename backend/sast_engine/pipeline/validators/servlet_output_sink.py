"""servlet_output_sink — reflected XSS needs request data written to an HTTP response.

``java-xss-jsp-servlet`` matched ``out.println`` inside ``System.out.println`` and
the word "request" inside a string literal, and a model sometimes calls a
``System.out`` line cross-site scripting. Whether a print is an XSS sink depends
on what its receiver is (SAST-03-010), and whether it is *reflected* XSS on
whether the printed value came from the request:

* the receiver is a logger, a process stream or a library type that is not a
  response writer -> not an HTTP output sink (``xss_sink_not_http_response``);
* an HTTP response writer, and every argument is a constant, number, boolean
  or enum -> nothing attacker-controlled can be written (``xss_arg_constrained``);
* an HTTP response writer and an argument built from a request accessor (or a
  local assigned from one) -> positive fact ``xss_request_in_response``;
* an HTTP response writer with no request-derived argument, for the rule's own
  regex hit -> ``xss_no_request_source``. A model finding is not dismissed on
  that ground: its source may be stored data or an exception message.

An unresolved receiver is no opinion — never a proof.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Set

from .. import jsp_scriptlets, output_sinks as sinks
from . import register
from ._logging import method_text
from .base import ValidatorResult, negative_proof, no_opinion, positive_fact

CWE_79 = ("CWE-79",)
XSS_RULE_IDS = ("java-xss-jsp-servlet",)

_REQUEST_TYPE_RE = re.compile(
    r"\b(?:Http)?ServletRequest(?:Wrapper)?\s+(\w+)\b|\bMultipartHttpServletRequest\s+(\w+)\b"
)
_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')
_SAFE_KINDS = {"string_literal", "constant", "numeric", "boolean", "enum"}
_DERIVE_ROUNDS = 3


def _strip_strings(text: str) -> str:
    return _STRING_RE.sub('""', text)


def _request_vars(file_text: str, path: str) -> Set[str]:
    names = {m.group(1) or m.group(2) for m in _REQUEST_TYPE_RE.finditer(file_text or "")}
    if path.lower().endswith(".jsp"):
        names.add("request")  # the JSP implicit object
    return {n for n in names if n}


def _derived_locals(method: str, request_vars: Set[str]) -> Set[str]:
    """Locals assigned (within a few hops) from an accessor of a request variable."""
    derived: Set[str] = set()
    assignments = [(m.group(1), _strip_strings(m.group(2)))
                   for m in re.finditer(r"\b(\w+)\s*=(?!=)\s*([^;]*);", method)]
    for _ in range(_DERIVE_ROUNDS):
        grew = False
        for name, rhs in assignments:
            if name in derived:
                continue
            if _mentions_request(rhs, request_vars, derived):
                derived.add(name)
                grew = True
        if not grew:
            break
    return derived


def _mentions_request(text: str, request_vars: Set[str], derived: Set[str]) -> bool:
    text = _strip_strings(text)
    for var in request_vars:
        if re.search(rf"\b{re.escape(var)}\s*\.\s*\w+\s*\(", text):
            return True
    return any(re.search(rf"\b{re.escape(name)}\b", text) for name in derived)


def _constrained(args: List[Dict[str, Any]]) -> bool:
    if not args:
        return True
    return all(set(str(a.get("kind") or "unknown").split("+")) <= _SAFE_KINDS for a in args)


@register("servlet_output_sink", 1, rule_ids=XSS_RULE_IDS, cwes=(79,))
def servlet_output_sink(finding, facts, ctx) -> ValidatorResult:
    path = finding.get("file_path") or ""
    if not facts or facts.get("lang") != "java" or not facts.get("call"):
        return no_opinion()
    call = facts["call"]
    sink = sinks.sink_class(facts, file_path=path)
    where = f"line {call.get('start_line')}"

    if sink.kind in (sinks.LOGGER, sinks.PROCESS_STREAM, sinks.OTHER):
        return negative_proof(
            "xss_sink_not_http_response",
            f"The call at {where} writes to {sink.detail or sink.kind}, not to an HTTP response.",
            applies_to_cwe=CWE_79,
        )
    if sink.kind != sinks.HTTP_RESPONSE:
        return no_opinion()

    args: List[Dict[str, Any]] = facts.get("args") or []
    if args and _constrained(args):
        kinds = ", ".join(sorted({str(a.get("kind")) for a in args}))
        return negative_proof(
            "xss_arg_constrained",
            f"The response write at {where} takes only constant or numeric values ({kinds}).",
            applies_to_cwe=CWE_79,
        )

    text = ctx.read_text(path) if path else None
    if text and path.lower().endswith(".jsp"):
        text = jsp_scriptlets.rewrite(text) or text  # only the Java parts are code
    request_vars = _request_vars(text or "", path)
    derived = _derived_locals(method_text(text, facts), request_vars) if request_vars else set()
    arg_text = " ".join(str(a.get("text") or "") for a in args)
    if request_vars and _mentions_request(arg_text, request_vars, derived):
        return positive_fact(
            "xss_request_in_response",
            f"A value taken from the request is written to the HTTP response at {where}.",
            applies_to_cwe=CWE_79,
        )
    if finding.get("kind") == "regex" and request_vars:
        return negative_proof(
            "xss_no_request_source",
            f"No argument of the response write at {where} comes from the request.",
            applies_to_cwe=CWE_79,
        )
    return no_opinion()
