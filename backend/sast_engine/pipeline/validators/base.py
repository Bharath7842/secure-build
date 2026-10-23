"""Types shared by the deterministic occurrence validators.

A validator looks at one finding and its resolved facts and answers one of:

* ``negative_proof(reason_tag, proof)`` — the occurrence is *not* what its rule
  says, and here is why (the match is a method declaration, not a call);
* ``positive_fact(reason_tag, proof)`` — the occurrence *is* unsafe by a
  checkable fact (a numeric binding is not involved; a string is concatenated
  into the statement);
* ``evidence_gap(missing)`` — the answer depends on something the scan has not
  resolved ("callee ``RequestsMgr.getCommMethod(String)`` body not resolved");
* ``note(reason_tag, text)`` — something worth recording that no verdict should
  depend on (the deployed log layout is not in the repository);
* ``no_opinion``.

VALIDATOR TEMPLATE
------------------

::

    @register("my_check", 1, rule_prefixes=("runtime-sink-sql-",))
    def my_check(finding, facts, ctx):
        if facts is None:
            return no_opinion()
        ...
        return negative_proof("some_tag", "one sentence a reviewer can verify")

A validator is pure and fast: no LLM, no network, no repository walk. Anything
beyond the current file goes through ``ctx``, which caches file reads.

NEVER return a negative proof because of a rule name, a file path, a logger
spelling or a severity. A negative proof dismisses a finding with no model and
no reviewer in the loop; it must rest on the resolved structure of *this*
occurrence (its parse, its binding, its constant value). Accuracy review gate 2
(§9.4) rejects the rest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Sequence, Tuple

NEGATIVE = "negative_proof"
POSITIVE = "positive_fact"
GAP = "evidence_gap"
NO_OPINION = "no_opinion"
# Recorded on the finding and counted, never settled and never shown to the model:
# "the deployed log layout is not in the repository" is something a reviewer should
# know, but it must not change a verdict that other evidence already supports.
NOTE = "note"

PROOF_MAX_CHARS = 200

# The scan's ValidatorContext rides on the shared usage dict under this key (as
# the LLM result cache does under llm_client.RESULT_CACHE_USAGE_KEY), so every
# stage that already passes `usage` reaches the call graph and SQL summaries
# without a new parameter. Never serialized: usage_cost_summary reads named keys.
VALIDATOR_CONTEXT_USAGE_KEY = "_validator_ctx"


def _cut(text: Optional[str]) -> Optional[str]:
    if text is None:
        return None
    text = " ".join(str(text).split())
    return text if len(text) <= PROOF_MAX_CHARS else text[: PROOF_MAX_CHARS - 1] + "…"


@dataclass(frozen=True)
class ValidatorResult:
    outcome: str
    reason_tag: Optional[str] = None
    proof: Optional[str] = None
    missing: Optional[str] = None
    # What kind of issue the occurrence is, when the check decides it: a
    # numeric value concatenated into SQL is `quality`, not injection; unsafe
    # SQL in a method nothing can reach is `inactive`. Changes the class, never
    # the verdict.
    issue_class: Optional[str] = None
    # The weakness classes this answer is about (`("CWE-117",)`). Empty means it
    # holds for whatever the finding claims. An answer that names its CWEs counts
    # only for a finding of one of them: a proof that a value cannot forge a log
    # line says nothing about the same value being sensitive data (CWE-532).
    applies_to_cwe: Tuple[str, ...] = ()


def negative_proof(reason_tag: str, proof: str, *, issue_class: Optional[str] = None,
                   applies_to_cwe: Sequence[str] = ()) -> ValidatorResult:
    return ValidatorResult(NEGATIVE, reason_tag=reason_tag, proof=_cut(proof), issue_class=issue_class,
                           applies_to_cwe=tuple(applies_to_cwe))


def positive_fact(reason_tag: str, proof: str, *, issue_class: Optional[str] = None,
                  applies_to_cwe: Sequence[str] = ()) -> ValidatorResult:
    return ValidatorResult(POSITIVE, reason_tag=reason_tag, proof=_cut(proof), issue_class=issue_class,
                           applies_to_cwe=tuple(applies_to_cwe))


def evidence_gap(missing: str, *, applies_to_cwe: Sequence[str] = ()) -> ValidatorResult:
    return ValidatorResult(GAP, missing=_cut(missing), applies_to_cwe=tuple(applies_to_cwe))


def note(reason_tag: str, text: str, *, applies_to_cwe: Sequence[str] = ()) -> ValidatorResult:
    return ValidatorResult(NOTE, reason_tag=reason_tag, proof=_cut(text), applies_to_cwe=tuple(applies_to_cwe))


def no_opinion() -> ValidatorResult:
    return ValidatorResult(NO_OPINION)


@dataclass
class ValidatorContext:
    """Read access a validator may use: file text (cached) and, when the scan
    built them, the call graph and SQL method summaries. ``file_text`` is pre-seeded with the file being
    scanned, so the common case never touches the disk."""

    file_text: Dict[str, str] = field(default_factory=dict)
    repo_root: Optional[Path] = None
    call_graph: Any = None
    # The scan's SQL method summaries (`sql_semantics.SqlSummaries`), when built.
    sql: Any = None
    # The repository's logging configuration, parsed on first use (SAST-03-050).
    _logging: Any = field(default=None, repr=False, compare=False)

    def logging_config(self) -> Any:
        if self._logging is None:
            from .. import logging_config

            self._logging = logging_config.load(self.repo_root)
        return self._logging

    def read_text(self, path: str) -> Optional[str]:
        if path in self.file_text:
            return self.file_text[path]
        if self.repo_root is None:
            return None
        try:
            text = (self.repo_root / path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        self.file_text[path] = text
        return text


ValidatorFn = Callable[[Dict[str, Any], Optional[Dict[str, Any]], ValidatorContext], ValidatorResult]
