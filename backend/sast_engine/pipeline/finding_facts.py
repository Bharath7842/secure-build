"""finding_facts.py — attach occurrence facts to findings, and run the
deterministic per-occurrence checks on them (EPIC-01).

`prepare_findings` is the one entry point the scan stages call, on a file's
findings, after the model or a rule produced them and before anything groups,
dedupes or publishes them:

1. `attach_facts` resolves each finding's AST facts once (`occurrence_facts`)
   and stores them as `finding["facts"]`.
2. The deterministic validators (`pipeline/validators`) run on each occurrence
   and may settle it: a proof it is not what the rule says, a fact that it
   is, or a statement of what evidence is missing. See `validators` for the
   fixed precedence against the model's verdict.

Both steps are best-effort and never raise: with no tree-sitter, an
unsupported language or an unparseable file there are simply no facts, and
every consumer behaves exactly as it did before facts existed.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence

from llm_client import bump_counter

from . import occurrence_facts


def match_span(finding: Dict[str, Any]) -> Optional[tuple]:
    """(start, end) columns of the regex match on the finding's line, when the
    hit carried them (LLM findings do not)."""
    start, end = finding.get("col_start"), finding.get("col_end")
    if start is None or end is None:
        return None
    try:
        return int(start), int(end)
    except (TypeError, ValueError):
        return None


def attach_facts(
    finding: Dict[str, Any],
    source_text: str,
    *,
    file_path: str = "",
    usage: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Set `finding["facts"]` and return them (None when there are none)."""
    path = finding.get("file_path") or file_path or ""
    lang = occurrence_facts._lang_for(path)
    if lang is None:
        return None
    span = match_span(finding)
    hint = None if span is not None else (finding.get("sink") or None)
    try:
        facts = occurrence_facts.facts_for(
            path, source_text, finding.get("line"), span, sink_hint=hint
        )
    except Exception:  # noqa: BLE001
        facts = None
    bump_counter(usage, "facts_coverage", f"{lang}.total")
    if facts is None:
        return None
    bump_counter(usage, "facts_coverage", f"{lang}.with_facts")
    finding["facts"] = dict(facts)
    _note_source_evidence(finding, source_text)
    return finding["facts"]


def _squash(text: str) -> str:
    return " ".join(str(text or "").split())


def source_in_text(source: str, text: str) -> bool:
    """Does the source expression a finding names appear in `text`? The model
    often names a source by its type (`TextMessage.getText()`) where the code
    has the variable (`message.getText()`), so a call is matched on its callee
    name and a dotted path on its last segment, not on the whole expression.
    The wording note after the expression ("orderId (method parameter)") is
    ignored."""
    expression = _squash(str(source or "").split(" (", 1)[0])
    if not expression:
        return False
    body = _squash(text)
    if expression in body:
        return True
    calls = re.findall(r"([A-Za-z_]\w*)\s*\(", expression)
    tail = calls[-1] if calls else re.split(r"[.\s]+", expression)[-1]
    return len(tail) >= 3 and re.search(rf"(?<![\w$]){re.escape(tail)}(?![\w$])", body) is not None


def _note_source_evidence(finding: Dict[str, Any], source_text: str) -> None:
    """`facts["source_in_method"]`: does the model's named `source` expression
    appear in the method the finding sits in? Publication uses it to tell a
    finding with a traced source from one that only asserts a source exists."""
    source = _squash(finding.get("source"))
    facts = finding.get("facts")
    enclosing = (facts or {}).get("enclosing")
    if not source or not enclosing:
        return
    lines = source_text.splitlines()
    start, end = int(enclosing.get("start_line") or 0), int(enclosing.get("end_line") or 0)
    if start < 1 or end < start:
        return
    facts["source_in_method"] = source_in_text(source, "\n".join(lines[start - 1:end]))


def prepare_findings(
    findings: Sequence[Dict[str, Any]],
    source_text: str,
    *,
    file_path: str = "",
    usage: Optional[Dict[str, Any]] = None,
    validators: bool = True,
) -> List[Dict[str, Any]]:
    """Attach facts to every finding of one file, then run the validators on
    each (unless `validators` is off). Mutates and returns `findings`."""
    fresh = [f for f in findings if not f.get("_prepared")]
    for finding in fresh:
        attach_facts(finding, source_text, file_path=file_path, usage=usage)
    for finding in fresh:
        finding["_prepared"] = True
    if validators and fresh:
        try:
            from . import validators as validator_registry

            validator_registry.apply_validators(
                fresh, source_text, file_path=file_path, usage=usage
            )
        except ImportError:  # the registry ships in the same epic; tolerate its absence
            pass
    return list(findings)


def facts_of(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    facts = finding.get("facts")
    return facts if isinstance(facts, dict) and facts else None
