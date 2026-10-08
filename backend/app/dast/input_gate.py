"""Loads the input-validation rule list and wraps the pure validator with the
counting and logging the active-testing loop needs (DAST-01-060).

Engine layer: depends on the domain, the standard library and the committed rule
file only. A rejected input is counted by reason and logged by rule id, length and a
short hash; the value itself is never kept, logged or persisted, so a rejected
payload can never end up as training data.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Callable, Iterable

from .domain.validation import (
    ProposedTest,
    RuleList,
    ValidatedTest,
    ValidationResult,
    parse_rule_list,
    validate_marker_value,
    validate_proposal,
    validate_test_input,
)

DEFAULT_RULES_PATH = Path(__file__).resolve().parent / "data" / "input_rules.json"

logger = logging.getLogger(__name__)


def load_rule_list(path: Path | str | None = None) -> RuleList:
    """Parse a rule file. Raises ValueError/OSError on a missing or malformed file."""
    with open(path or DEFAULT_RULES_PATH, encoding="utf-8") as handle:
        return parse_rule_list(json.load(handle))


@lru_cache(maxsize=1)
def default_rule_list() -> RuleList:
    return load_rule_list()


class InputGate:
    """One per scan. `check` is the only way the active-testing loop should decide
    whether a model-generated input may be sent."""

    def __init__(
        self,
        rules: RuleList | None = None,
        *,
        safe_mode: bool = True,
        allow_state_changing: bool = False,
        allowed_hosts: Iterable[str] | None = None,
        log: Callable[[str], None] | None = None,
    ) -> None:
        self._rules = rules or default_rule_list()
        # None: no host check (unit tests of the validator). A set: an input may name only these hosts.
        self._allowed_hosts = frozenset(h.lower() for h in allowed_hosts) if allowed_hosts is not None else None
        self._safe_mode = safe_mode
        self._allow_state_changing = allow_state_changing
        self._log = log
        self._lock = threading.Lock()
        self.accepted = 0
        self.rejected_by_rule: Counter[str] = Counter()

    @property
    def rejected(self) -> int:
        return sum(self.rejected_by_rule.values())

    def check(self, test: ProposedTest) -> ValidationResult:
        try:
            result = validate_test_input(
                test,
                self._rules,
                safe_mode=self._safe_mode,
                allow_state_changing=self._allow_state_changing,
                allowed_hosts=self._allowed_hosts,
            )
        except Exception as exc:  # noqa: BLE001 - fail closed: an input we cannot judge is not sent
            result = ValidationResult(False, f"validator error: {type(exc).__name__}", "validator-error")
        with self._lock:
            if result.ok:
                self.accepted += 1
            else:
                self.rejected_by_rule[result.rule_id] += 1
        if not result.ok:
            self._record_rejection(test, result)
        return result

    def validate(
        self,
        *,
        method: str,
        check_id: str,
        parameter: str,
        location: str,
        value: str,
        expected_signal: str = "",
        control_value: str = "",
    ) -> ValidatedTest | None:
        """The active loop's entry point: a `ValidatedTest` for an acceptable proposal, else None
        (counted by rule and logged by rule id, length and hash; the value is never kept)."""
        try:
            result, validated = validate_proposal(
                check_id=check_id, parameter=parameter, location=location, method=method, value=value,
                expected_signal=expected_signal, control_value=control_value, rules=self._rules,
                safe_mode=self._safe_mode, allow_state_changing=self._allow_state_changing, allowed_hosts=self._allowed_hosts,
            )
        except Exception as exc:  # noqa: BLE001 - fail closed
            result, validated = ValidationResult(False, f"validator error: {type(exc).__name__}", "validator-error"), None
        with self._lock:
            if result.ok:
                self.accepted += 1
            else:
                self.rejected_by_rule[result.rule_id] += 1
        if not result.ok:
            self._record_rejection(ProposedTest(method, location, value), result)
        return validated

    def check_marker(self, value: str) -> ValidationResult:
        """Whether a browser marker may be typed. Counts and logs a rejection the same way `check` does."""
        try:
            result = validate_marker_value(value, self._rules, allowed_hosts=self._allowed_hosts)
        except Exception as exc:  # noqa: BLE001 - fail closed
            result = ValidationResult(False, f"validator error: {type(exc).__name__}", "validator-error")
        with self._lock:
            if result.ok:
                self.accepted += 1
            else:
                self.rejected_by_rule[result.rule_id] += 1
        if not result.ok:
            self._record_rejection(ProposedTest("GET", "query", value), result)
        return result

    def _record_rejection(self, test: ProposedTest, result: ValidationResult) -> None:
        value = test.value if isinstance(test.value, str) else str(test.value)
        digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:8]
        line = (
            f"[safety] test input rejected rule={result.rule_id} method={(test.method or '').upper()} "
            f"location={test.location} len={len(value)} sha256={digest}: {result.reason}"
        )
        logger.warning(line)
        if self._log is not None:
            try:
                self._log(line)
            except Exception:  # noqa: BLE001 - logging must never break the scan
                logger.debug("scan log callback failed", exc_info=True)

    def summary(self) -> dict:
        return {"accepted": self.accepted, "rejected": self.rejected, "rejected_by_rule": dict(self.rejected_by_rule)}
