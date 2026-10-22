"""Types shared by the deterministic occurrence validators.

A validator looks at one finding and its resolved facts and answers one of:

* ``negative_proof(reason_tag, proof)`` — the occurrence is *not* what its rule
  says, and here is why (the match is a method declaration, not a call);
* ``positive_fact(reason_tag, proof)`` — the occurrence *is* unsafe by a
  checkable fact (a numeric binding is not involved; a string is concatenated
  into the statement);
* ``evidence_gap(missing)`` — the answer depends on something the scan has not
  resolved ("callee ``RequestsMgr.getCommMethod(String)`` body not resolved");
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
from typing import Any, Callable, Dict, Optional

NEGATIVE = "negative_proof"
POSITIVE = "positive_fact"
GAP = "evidence_gap"
NO_OPINION = "no_opinion"

PROOF_MAX_CHARS = 200


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


def negative_proof(reason_tag: str, proof: str, *, issue_class: Optional[str] = None) -> ValidatorResult:
    return ValidatorResult(NEGATIVE, reason_tag=reason_tag, proof=_cut(proof), issue_class=issue_class)


def positive_fact(reason_tag: str, proof: str, *, issue_class: Optional[str] = None) -> ValidatorResult:
    return ValidatorResult(POSITIVE, reason_tag=reason_tag, proof=_cut(proof), issue_class=issue_class)


def evidence_gap(missing: str) -> ValidatorResult:
    return ValidatorResult(GAP, missing=_cut(missing))


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
