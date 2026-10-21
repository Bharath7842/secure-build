"""stub_method — a sink rule matched in a method whose body is a stub.

A body that is only ``return <literal>;``, empty, or ``throw new
UnsupportedOperationException(...)`` contains no statement that could reach a
sink, whatever the rule matched there. The proof applies to that occurrence
only: the real implementations of the same method elsewhere are different
occurrences with different facts, and are not touched.
"""

from __future__ import annotations

from . import register
from .base import ValidatorResult, negative_proof, no_opinion


@register("stub_method", 1, rule_prefixes=("runtime-sink-",))
def stub_method(finding, facts, ctx) -> ValidatorResult:
    if not facts or not facts.get("is_stub"):
        return no_opinion()
    enclosing = facts.get("enclosing") or {}
    name = enclosing.get("method") or "the method"
    return negative_proof(
        "stub_no_sink",
        f"{name}() is a stub (its body only returns a literal or throws "
        "UnsupportedOperationException), so it reaches no sink.",
    )
