"""wrapper_call_identity — does this call reach the wrapper its rule was derived from?

A `runtime-sink-*` rule is derived from one project method (owner, signature,
the parameters that reach its sink — `derive_rules`), but its regex is only
`\\bname\\s*\\(`: it matches every same-named call. This decides each match
from the call's resolved facts:

* **Negative proof `wrapper_identity_mismatch`** — the call resolves to a
  different owner (one that is neither the wrapper's class nor a type the
  wrapper's class extends or implements) or passes a different number of
  arguments (#62: the DAO's `getPortID(long)` is not the message's
  `getPortID()`).
* **Negative proof `wrapper_arg_constant`** — every argument at a parameter
  that reaches the sink is a constant here, so the call cannot carry taint.
* **No opinion** — the receiver cannot be resolved, or the call is the
  wrapper with a non-constant argument (the SQL checks judge the rest).
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional, Set

from . import register
from .base import ValidatorResult, negative_proof, no_opinion

_CONSTANT_KINDS = frozenset({"string_literal", "constant", "boolean", "enum"})
_NUMBER_LITERAL_RE = re.compile(r"^-?\d[\d_]*(?:\.\d+)?[lLfFdD]?$")


def _supertypes(graph: Any, fqcn: str) -> Set[str]:
    """`fqcn` and every in-repo type it extends or implements."""
    from pipeline import call_graph as cg

    out: Set[str] = set()
    queue = [fqcn]
    while queue:
        current = queue.pop()
        if current in out:
            continue
        out.add(current)
        jtype = graph.types.get(current)
        if jtype is None:
            continue
        package, imports, stars = graph._file_imports.get(jtype.file, ("", {}, set()))
        for super_name in jtype.super_types:
            resolved = cg._resolve_simple(super_name, package=package, imports=imports, stars=stars, graph=graph)
            if resolved:
                queue.append(resolved)
    return out


def _receiver_owner(call: Dict[str, Any], graph: Any) -> Optional[str]:
    """The receiver's type as an FQN, from the facts, else by its declared
    simple name when the repo has exactly one type of that name."""
    fqn = call.get("receiver_fqn")
    if fqn:
        return fqn
    simple = call.get("receiver_type")
    if simple and graph is not None:
        matches = graph.types_by_simple.get(simple) or []
        if len(matches) == 1:
            return matches[0]
    return None


def _is_constant(arg: Dict[str, Any]) -> bool:
    kind = str(arg.get("kind") or "")
    return kind in _CONSTANT_KINDS or (kind == "numeric" and bool(_NUMBER_LITERAL_RE.match(str(arg.get("text") or ""))))


@register("wrapper_call_identity", 1, rule_prefixes=("runtime-sink-",))
def wrapper_call_identity(finding, facts, ctx) -> ValidatorResult:
    wrapper = finding.get("wrapper")
    call = (facts or {}).get("call") if facts else None
    if not wrapper or not call or facts.get("is_declaration"):
        return no_opinion()
    name = wrapper.get("name")
    if name and call.get("callee") != name:
        return no_opinion()  # the match is not this call (another call on the line)
    owner, signature = wrapper.get("owner"), wrapper.get("signature") or name
    arity = wrapper.get("arity")
    if arity is not None and call.get("arity") is not None and int(call["arity"]) != int(arity):
        return negative_proof("wrapper_identity_mismatch", (
            f"`{call.get('text') or name}` passes {call['arity']} argument(s); the rule's wrapper "
            f"{owner}.{signature} takes {arity}, so this is a different method."
        ))
    graph = getattr(ctx, "call_graph", None)
    receiver = _receiver_owner(call, graph)
    if receiver is None:
        return no_opinion()
    if receiver != owner:
        # A call on a supertype the wrapper's class implements may dispatch to it.
        related = graph is not None and (receiver in _supertypes(graph, owner) or owner in _supertypes(graph, receiver))
        if not related:
            return negative_proof("wrapper_identity_mismatch", (
                f"`{call.get('text') or name}` is called on {receiver}, not on the rule's wrapper "
                f"{owner}.{signature}: a same-named method of another type."
            ))
    tainted = wrapper.get("tainted_params")
    args = facts.get("args") or []
    if tainted:
        at = [args[i] for i in tainted if i < len(args)]
        if at and all(_is_constant(a) for a in at):
            names = ", ".join(f"`{a.get('text')}`" for a in at[:3])
            return negative_proof("wrapper_arg_constant", (
                f"The call passes only constants ({names}) at the parameters of {owner}.{signature} "
                "that reach its sink, so it carries no outside input."
            ))
    return no_opinion()
