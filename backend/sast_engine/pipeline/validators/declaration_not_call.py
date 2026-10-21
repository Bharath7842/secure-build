"""declaration_not_call — a call-site rule matched on a method *declaration*.

A derived ``runtime-sink-*`` rule looks for call sites of a project method that
contains a typed sink (``\\bdeleteJob\\s*\\(``). The same text appears where that
method is declared (``public int deleteJob(int id) {``), and a declaration is
not a call: nothing is passed to it there. The proof is structural — the
occurrence's own parse says the match sits in a method header — not a guess
from the method's name or location.
"""

from __future__ import annotations

from . import register
from .base import ValidatorResult, negative_proof, no_opinion


@register("declaration_not_call", 1, rule_prefixes=("runtime-sink-",))
def declaration_not_call(finding, facts, ctx) -> ValidatorResult:
    if not facts or not facts.get("is_declaration"):
        return no_opinion()
    enclosing = facts.get("enclosing") or {}
    name = enclosing.get("method") or "the method"
    return negative_proof(
        "match_is_declaration",
        f"The match is the declaration of {name}() (line {enclosing.get('start_line')}), "
        "not a call to it.",
    )
