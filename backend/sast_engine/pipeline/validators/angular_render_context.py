"""angular_render_context — follow an Angular value to where the page renders it.

A CWE-79/CWE-94 finding on a translation lookup or a component property is
judged by the component's own template and class (`angular_render`):

* every consumer renders it as text (`{{ }}`, a text binding) and no custom
  translation pipeline sits between the dictionary and the page -> negative
  proof ``angular_text_interpolation`` listing each template line;
* the only other consumers are `[innerHTML]`, which Angular sanitises ->
  negative proof ``angular_sanitised_html`` (content can be injected, script
  cannot run);
* a trusted-value bypass, a native-element write or an evaluator uses it ->
  positive fact ``angular_unsafe_render``;
* a custom translation compiler / handler, a template that cannot be read, a
  child component that receives it, or no consumer at all -> a named evidence gap.

CWE-94 needs an evaluator: a dictionary lookup shown as text is never code
execution. The rules that *are* the dangerous contexts (`innerhtml-assign`,
bypass, renderer) are never touched, and each finding is judged by its own
property's consumers, not by another branch's.
"""

from __future__ import annotations

from typing import List

from .. import angular_render as ar
from . import register
from .base import ValidatorResult, evidence_gap, negative_proof, no_opinion, positive_fact

SCOPE = ("CWE-79", "CWE-94")


@register("angular_render_context", 1, cwes=(79, 94))
def angular_render_context(finding, facts, ctx) -> ValidatorResult:
    path = finding.get("file_path") or ""
    if not path.lower().endswith(".ts") or finding.get("rule_id") in ar.POSITIVE_RULE_IDS:
        return no_opinion()
    text = ctx.read_text(path)
    line = finding.get("line")
    if not text or not line:
        return no_opinion()
    analysis = ar.analyze(text, path, int(line), ctx.read_text)
    if analysis is None:
        return no_opinion()
    cwe_digits = "".join(ch for ch in str(finding.get("cwe") or "") if ch.isdigit())
    names = ", ".join(analysis.properties)
    unsafe = [c for c in analysis.consumers if c.context in ar.UNSAFE]
    unknown = [c for c in analysis.consumers if c.context == ar.UNKNOWN]

    if cwe_digits == "94":
        evaluators = [c for c in analysis.consumers if c.context == ar.EVALUATOR]
        if evaluators:
            return positive_fact("angular_unsafe_render",
                                 f"{names} reaches an evaluator at {evaluators[0].where}.", applies_to_cwe=SCOPE)
        if unsafe or unknown or analysis.problems:
            return no_opinion()
        return negative_proof(
            "angular_no_evaluator",
            f"{names} is only displayed ({_where(analysis.consumers)}); a dictionary lookup is not code execution.",
            applies_to_cwe=SCOPE,
        )

    if unsafe:
        return positive_fact(
            "angular_unsafe_render",
            f"{names} reaches {unsafe[0].context} at {unsafe[0].where}: {unsafe[0].detail}".strip(": "),
            applies_to_cwe=SCOPE,
        )
    missing: List[str] = list(analysis.problems) + [f"{c.detail} ({c.where})" for c in unknown]
    if analysis.anchor == "translate":
        custom = ctx.custom_translation_pipeline()
        if custom:
            missing.append(f"custom translation component {custom[0]} sits between the dictionary and the page")
    if missing:
        return evidence_gap("angular render context: " + "; ".join(missing), applies_to_cwe=SCOPE)
    if all(c.context == ar.TEXT for c in analysis.consumers):
        return negative_proof(
            "angular_text_interpolation",
            f"{names} is rendered only as escaped text: {_where(analysis.consumers)}.",
            applies_to_cwe=SCOPE,
        )
    return negative_proof(
        "angular_sanitised_html",
        f"{names} is rendered as text or Angular-sanitised HTML ({_where(analysis.consumers)}); "
        "script cannot run from it.",
        applies_to_cwe=SCOPE,
    )


def _where(consumers) -> str:
    return ", ".join(dict.fromkeys(c.where for c in consumers))[:150]
