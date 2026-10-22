"""explanation_check.py — does a finding's explanation contradict its own code
or verdict? (SAST-01-090)

A published finding is read as a settled answer. Before it is, five
deterministic checks look for an explanation that cannot be right:

1. ``sink_not_on_line`` — the sink the finding names is not in the call it is
   anchored on (a finding that discusses line 1139 anchored at 1135);
2. ``source_not_in_scope`` — the source it names is not in the enclosing method
   or on the flow path;
3. ``verdict_reason_mismatch`` — a true positive whose own reason says the
   construct is safe ("parameterized", "not exploitable"), or a false positive
   whose reason asserts exploitation;
4. ``fix_already_present`` — the suggested fix is a construct the anchored call
   already contains (recommending ``logger.error(msg, ex)`` when that is the code);
5. ``unproven_no_callers`` — the reason claims "no callers" / "dead code" while
   the call graph is incomplete.

The phrase lists below are short and explicit, and they are only ever a
*trigger*: a contradiction earns one targeted retry (the same prompt plus a
``Deterministic facts:`` block naming it) and, if it survives, an ``unverified``
finding with ``explanation_contradiction`` — never a dismissal. A wording check
must not be able to discard a real vulnerability (review §5.8).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence

from llm_client import bump_counter

from .finding_facts import source_in_text

CHECK_SINK = "sink_not_on_line"
CHECK_SOURCE = "source_not_in_scope"
CHECK_REASON = "verdict_reason_mismatch"
CHECK_FIX = "fix_already_present"
CHECK_CALLERS = "unproven_no_callers"
CHECKS = (CHECK_SINK, CHECK_SOURCE, CHECK_REASON, CHECK_FIX, CHECK_CALLERS)

# --- phrase lists (the only place wording is judged) ------------------------------
_SAFE_PHRASES = re.compile(
    r"\b(parameteri[sz]ed|prepared statement|bind variables?|bound (?:as )?(?:a )?parameters?|"
    r"no (?:sql )?injection risk|not exploitable|cannot be exploited|is safe|are safe|"
    r"not vulnerable|hard-?coded constant|compile-time constant)\b",
    re.IGNORECASE,
)
_EXPLOIT_PHRASES = re.compile(
    r"\b(is exploitable|can be exploited|attacker can(?!not)|attackers can(?!not)|"
    r"allows? (?:an )?(?:attacker|injection)|is vulnerable to)\b",
    re.IGNORECASE,
)
_NO_CALLERS_PHRASES = re.compile(
    r"\b(no callers|never called|not called (?:from|by|anywhere)|unused|dead code|unreachable code)\b",
    re.IGNORECASE,
)
# A phrase negated just before it ("not parameterized", "no prepared statement")
# says the opposite of what it matches.
_NEGATION_BEFORE = re.compile(r"\b(?:not|no|never|without|isn't|aren't|instead of|rather than|lacks?)\W+(?:\w+\W+){0,2}$",
                              re.IGNORECASE)
_CODE_SPAN = re.compile(r"`([^`]{6,120})`|\b([A-Za-z_][\w.]*\([^()]{0,80}\))")


def _squash(text: Any) -> str:
    return " ".join(str(text or "").split())


def _unnegated(pattern: "re.Pattern[str]", text: str) -> Optional[str]:
    for match in pattern.finditer(text):
        if not _NEGATION_BEFORE.search(text[: match.start()]):
            return match.group(0)
    return None


def _contradiction(check: str, detail: str) -> Dict[str, str]:
    return {"check": check, "detail": detail}


def _anchored_text(finding: Dict[str, Any], facts: Optional[Dict[str, Any]], source_text: str) -> str:
    """The code a finding's sink must be in: the resolved call, else its line."""
    call = (facts or {}).get("call") or {}
    if call.get("text"):
        return _squash(call["text"])
    lines = source_text.splitlines()
    line = int(finding.get("line") or 0)
    return _squash(lines[line - 1]) if 0 < line <= len(lines) else ""


def _sink_names(sink: str) -> List[str]:
    """Callee names a sink statement commits to, or [] when it is prose and so
    cannot be judged. ``stmt.executeQuery`` -> executeQuery;
    ``connection.prepareStatement(sql)`` -> prepareStatement; "logger call in
    AuthService.login" -> [] (a sentence, not an expression)."""
    sink = _squash(sink)
    if not sink:
        return []
    names = re.findall(r"([A-Za-z_]\w*)\s*\(", sink)
    if names:
        return names
    if re.fullmatch(r"[\w$]+(?:\.[\w$]+)*", sink):
        return [sink.rsplit(".", 1)[-1]]
    return []


def _looks_like_code(expression: str) -> bool:
    return bool(re.fullmatch(r"[\w$.]+(?:\(.*\))?", expression)) or "(" in expression


def check_explanation(
    finding: Dict[str, Any],
    facts: Optional[Dict[str, Any]],
    source_text: str,
    *,
    call_graph_complete: bool = False,
) -> List[Dict[str, str]]:
    """The contradictions in one finding's explanation (empty when it is
    consistent). Pure; no LLM. Undecided findings have no explanation to check."""
    verdict = finding.get("verdict")
    if verdict not in ("true_positive", "false_positive"):
        return []
    found: List[Dict[str, str]] = []
    reason = str(finding.get("verdict_reason") or "")
    anchored = _anchored_text(finding, facts, source_text)

    # 1. the named sink is not in the anchored call
    names = _sink_names(finding.get("sink") or "")
    if names and anchored and not any(name in anchored for name in names):
        found.append(_contradiction(
            CHECK_SINK,
            f"the finding names the sink `{_squash(finding.get('sink'))}`, but the code at line "
            f"{finding.get('line')} is `{anchored[:160]}`, which does not contain it",
        ))

    # 2. the named source is not in the method / on the flow path
    source = _squash(finding.get("source")).split(" (", 1)[0]
    if source and _looks_like_code(source):
        if finding.get("kind") == "flow" and finding.get("flow_path"):
            in_scope: Optional[bool] = any(
                source_in_text(source, f"{step.get('snippet') or ''}\n{step.get('label') or ''}")
                for step in finding["flow_path"]
            )
        else:
            in_scope = (facts or {}).get("source_in_method")
        if in_scope is False:
            found.append(_contradiction(
                CHECK_SOURCE,
                f"the finding names the source `{source}`, which does not appear in the enclosing "
                "method" + (" or on the flow path" if finding.get("kind") == "flow" else ""),
            ))

    # 3. the verdict and the reason say opposite things
    if verdict == "true_positive":
        phrase = _unnegated(_SAFE_PHRASES, reason)
        if phrase:
            found.append(_contradiction(
                CHECK_REASON, f"the verdict is true_positive but its reason says the code is safe (\"{phrase}\")"))
    else:
        phrase = _unnegated(_EXPLOIT_PHRASES, reason)
        if phrase:
            found.append(_contradiction(
                CHECK_REASON, f"the verdict is false_positive but its reason asserts exploitation (\"{phrase}\")"))

    # 4. the fix is already in the code
    fix = str(finding.get("ai_fix") or "")
    statement = _squash((facts or {}).get("statement")) or anchored
    for match in _CODE_SPAN.finditer(fix):
        span = _squash(match.group(1) or match.group(2))
        if len(span) >= 8 and "(" in span and span in _squash(statement + " " + anchored):
            found.append(_contradiction(
                CHECK_FIX, f"the suggested fix `{span}` is what the code at line {finding.get('line')} already does"))
            break

    # 5. "no callers" with a call graph that cannot prove it (EPIC-02: the SQL
    # check records a proven `unreferenced` status on the facts)
    proven = (facts or {}).get("reachability_status") == "unreferenced"
    if not call_graph_complete and not proven and _unnegated(_NO_CALLERS_PHRASES, reason):
        found.append(_contradiction(
            CHECK_CALLERS,
            "the reason claims the code has no callers or is dead, but the call graph is incomplete "
            "and cannot prove that"))
    return found


def contradictions_block(items: Sequence[Dict[str, Any]], *, labels: Optional[Sequence[str]] = None) -> str:
    """The ``Deterministic facts:`` text for a retry prompt. Empty when no item
    carries a contradiction."""
    lines: List[str] = []
    for position, item in enumerate(items):
        label = labels[position] if labels else str(position + 1)
        for c in item.get("contradictions") or []:
            lines.append(f"- {label}: your answer contradicts the code — {c['detail']}. "
                         "Re-read the code and answer again.")
    return ("Deterministic facts:\n" + "\n".join(lines)) if lines else ""


def mark_contradicted(finding: Dict[str, Any]) -> Dict[str, Any]:
    """A finding whose explanation still contradicts itself: unresolved, with the
    contradictions listed. Never a dismissal, whatever the verdict was."""
    contradictions = finding.get("contradictions") or []
    prior_verdict = finding.get("verdict")
    listed = "; ".join(c["detail"] for c in contradictions)
    finding.update(
        verdict="unverified", unresolved_reason="explanation_contradiction",
        confidence=None, ai_fix=None,
        verdict_reason=f"The explanation contradicts the code or its own verdict: {listed}. "
                       f"(The model's verdict was {prior_verdict}.)",
    )
    finding.setdefault("decisions", []).append({
        "stage": "explanation_retry", "actor": "explanation_check",
        "verdict": "unverified", "confidence": None,
        "unresolved_reason": "explanation_contradiction", "verdict_reason": finding["verdict_reason"],
        "detail": {"contradictions": contradictions, "model_verdict": prior_verdict},
    })
    return finding


def annotate(
    findings: Sequence[Dict[str, Any]],
    source_text: str,
    *,
    usage: Optional[Dict[str, Any]] = None,
    call_graph_complete: bool = False,
) -> List[Dict[str, Any]]:
    """Run the checks on every finding, set ``finding["contradictions"]`` and
    count them; returns the contradicted ones."""
    contradicted: List[Dict[str, Any]] = []
    for finding in findings:
        facts = finding.get("facts") if isinstance(finding.get("facts"), dict) else None
        found = check_explanation(finding, facts, source_text, call_graph_complete=call_graph_complete)
        if found:
            finding["contradictions"] = found
            contradicted.append(finding)
            for c in found:
                bump_counter(usage, "explanation_contradictions", c["check"])
        else:
            finding.pop("contradictions", None)
    return contradicted
