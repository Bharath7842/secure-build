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
    return finding["facts"]


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
    for finding in findings:
        attach_facts(finding, source_text, file_path=file_path, usage=usage)
    if validators:
        try:
            from . import validators as validator_registry

            validator_registry.apply_validators(
                findings, source_text, file_path=file_path, usage=usage
            )
        except ImportError:  # the registry ships in the same epic; tolerate its absence
            pass
    return list(findings)


def facts_of(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    facts = finding.get("facts")
    return facts if isinstance(facts, dict) and facts else None
