"""log_value_domain — a value that cannot carry a line break cannot forge a log.

CWE-117 needs text that can hold a newline or a delimiter. A log call whose
every non-literal argument is a constant, a number, a boolean, an enum value or
a count (``"rows: " + count``, ``jobId`` after ``int jobId = parseInt(s)``, a
getter declared to return a ``BigInteger``) cannot, whoever the caller is. The
proof is the type of what is logged — resolved from the parse, the call
graph's method declarations and a small table of JDK methods — never its name.

* a constant or numeric argument whose type is resolved is safe;
* a getter on a project class is safe only when *every* method of that name
  declared on the type returns a number or boolean; unresolved is unknown;
* ``ServletRequest.getLocale()`` is not proven safe: the container parses
  ``Accept-Language`` and a ``Locale`` serialises to the container's grammar,
  so the answer is an evidence gap naming that;
* any other argument (a string, an exception, an unresolved call) gives no
  opinion here.

This says nothing about sensitive data (CWE-532): a numeric account number can
still be a leak, so the proof is scoped to CWE-117.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from .. import output_sinks as sinks
from . import register
from ._logging import CWE_117, LOG_RULE_IDS, LOG_RULE_PREFIXES, logger_call
from .base import ValidatorResult, evidence_gap, negative_proof, no_opinion

SAFE_KINDS = frozenset({"string_literal", "constant", "numeric", "boolean", "enum"})
SAFE_RETURN_TYPES = frozenset({
    "int", "long", "short", "byte", "float", "double", "boolean", "char",
    "Integer", "Long", "Short", "Byte", "Float", "Double", "Boolean", "Character",
    "BigInteger", "BigDecimal", "AtomicInteger", "AtomicLong", "AtomicBoolean",
})
# JDK methods that return a number or boolean, applied only to a declared type
# the project does not define (a project class's own `size()` is resolved from
# its declaration instead).
JDK_NUMERIC_METHODS = frozenset({
    "size", "length", "isEmpty", "ordinal", "intValue", "longValue", "doubleValue", "hashCode",
    "indexOf", "lastIndexOf", "executeUpdate", "getUpdateCount", "getRow", "getMaxRows",
    "parseInt", "parseLong", "parseShort", "parseByte", "parseDouble", "parseFloat",
    "currentTimeMillis", "nanoTime", "availableProcessors", "freeMemory", "totalMemory",
})
REQUEST_TYPES = frozenset({"HttpServletRequest", "ServletRequest"})
LOCALE_GAP = (
    "container Accept-Language parsing and Locale serialisation: a Locale from the request is "
    "constrained only to the container's grammar, which is not in the repository"
)


def _project_methods(graph: Any, simple: str, name: str) -> Optional[List[Any]]:
    """Every method named ``name`` declared on the project type ``simple`` (and,
    for an interface, nowhere else), or None when the type is not the project's."""
    if graph is None:
        return None
    fqcns = graph.types_by_simple.get(simple)
    if not fqcns:
        return None
    found: List[Any] = []
    for fqcn in fqcns:
        jtype = graph.types.get(fqcn)
        if jtype is None:
            continue
        found.extend(graph.methods[k] for k in jtype.methods
                     if k in graph.methods and graph.methods[k].name == name)
    return found


def _via_is_safe(via: str, graph: Any) -> Tuple[Optional[bool], str]:
    """(True safe | False locale-like | None unknown, description) for one
    ``Type.method`` call result."""
    declared, _, method = via.rpartition(".")
    if declared in REQUEST_TYPES and method == "getLocale":
        return False, f"{declared}.getLocale()"
    project = _project_methods(graph, declared, method) if declared and declared != "?" else None
    if project is not None:
        if project and all(m.return_type in SAFE_RETURN_TYPES for m in project):
            return True, f"{declared}.{method}() returns {project[0].return_type}"
        return None, f"{declared}.{method}()"
    if declared and declared != "?" and method in JDK_NUMERIC_METHODS:
        return True, f"{declared}.{method}() returns a number"
    return None, f"{declared or '?'}.{method}()"


def classify_arguments(args: List[Dict[str, Any]], graph: Any) -> Tuple[List[str], bool, bool]:
    """(descriptions, all_safe_or_locale, has_locale)."""
    described: List[str] = []
    locale = False
    for index, arg in enumerate(args, 1):
        kinds = set(str(arg.get("kind") or "unknown").split("+"))
        text = str(arg.get("text") or "")
        if kinds <= SAFE_KINDS:
            described.append(f"{index}: {text[:30]} ({'/'.join(sorted(kinds))})")
            continue
        extra = kinds - SAFE_KINDS
        if extra != {"call_result"}:
            return described, False, locale
        vias = [v for v in str(arg.get("via") or "").split(",") if v]
        if not vias:
            return described, False, locale
        for via in vias:
            safe, what = _via_is_safe(via, graph)
            if safe is None:
                return described, False, locale
            if safe is False:
                locale = True
            described.append(f"{index}: {what}")
    return described, True, locale


@register("log_value_domain", 1, rule_ids=LOG_RULE_IDS, rule_prefixes=LOG_RULE_PREFIXES, cwes=(117,))
def log_value_domain(finding, facts, ctx) -> ValidatorResult:
    sink = logger_call(facts, finding.get("file_path") or "", ctx)
    if sink is None or sink.kind != sinks.LOGGER:
        return no_opinion()
    args = facts.get("args") or []
    if not args:
        return no_opinion()
    described, ok, locale = classify_arguments(args, getattr(ctx, "call_graph", None))
    if not ok:
        return no_opinion()
    line = facts["call"].get("start_line")
    if locale:
        return evidence_gap(LOCALE_GAP, applies_to_cwe=CWE_117)
    return negative_proof(
        "log_arg_constrained",
        f"Every argument of the log call at line {line} is a constant, number, boolean or enum: "
        + "; ".join(described) + ".",
        applies_to_cwe=CWE_117,
    )
