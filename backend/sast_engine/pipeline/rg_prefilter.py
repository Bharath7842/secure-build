"""Conservative ripgrep prefilter for the regex catalog pass.

The catalog is matched with Python `re` (regex_scan.scan_text_by_rule), which
stays the only authority on hits, line numbers and matched text. ripgrep only
narrows *which (file, rule) pairs Python looks at*, and only where that can
never drop a hit:

* For each rule, `required_literal` walks Python's own parse of the pattern
  for a run of literal characters every match must contain. No rg-syntax
  translation is involved, so rg/Python regex dialect differences can't
  matter: rg runs the literal with `--fixed-strings`.
* Under IGNORECASE the run breaks at characters whose Python case folding
  differs from Rust's simple folding (`i`/`I`: Python also matches U+0130 and
  U+0131) and at non-ASCII characters; a local inline-flag group, or no
  literal of MIN_LITERAL_CHARS, leaves the rule ineligible (full Python scan).
* rg runs in `exhaustive` mode (hidden, symlinked, oversized and NUL-byte
  files too) and a search that timed out or was truncated makes its rules
  ineligible rather than trusting a partial file list.

The superset property — every file with a Python hit for an eligible rule is
in that rule's candidate set — is asserted by tests/test_rg_prefilter.py over
the test fixtures; any violation is a bug here.
"""

from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

try:  # Python 3.11+
    from re import _parser as sre_parse  # type: ignore[attr-defined]
    from re import _constants as sre_constants  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover — 3.10 and older
    import sre_constants  # type: ignore[no-redef]
    import sre_parse  # type: ignore[no-redef]

from pipeline.hunt.rg_runner import RgRunner
from pipeline.regex_scan import RegexRule

MIN_LITERAL_CHARS = 4
# Characters Python's IGNORECASE matches against more code points than
# Rust's simple case folding does (U+0130/U+0131 for i/I).
_UNSAFE_FOLD_CHARS = frozenset("iI")

_LITERAL = sre_constants.LITERAL
_SUBPATTERN = sre_constants.SUBPATTERN
_REPEATS = (sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT)
_POSSESSIVE = getattr(sre_constants, "POSSESSIVE_REPEAT", None)
_ATOMIC = getattr(sre_constants, "ATOMIC_GROUP", None)


class _Ineligible(Exception):
    pass


def required_literal(pattern: str) -> Optional[Tuple[str, bool]]:
    """(literal, ignore_case) every match of `pattern` must contain, or None
    when no safe literal of MIN_LITERAL_CHARS exists."""
    try:
        parsed = sre_parse.parse(pattern)
    except (re.error, RecursionError):
        return None
    ignore_case = bool(parsed.state.flags & re.IGNORECASE)
    runs: List[str] = []
    try:
        _collect_runs(list(parsed), ignore_case, runs)
    except _Ineligible:
        return None
    best = max(runs, key=len, default="")
    return (best, ignore_case) if len(best) >= MIN_LITERAL_CHARS else None


def _collect_runs(items: List[Tuple], ignore_case: bool, runs: List[str]) -> None:
    """Append every maximal run of consecutive required literal characters
    in this sequence (and in required sub-sequences) to `runs`."""
    current: List[str] = []

    def flush() -> None:
        if current:
            runs.append("".join(current))
            current.clear()

    for op, av in items:
        if op == _LITERAL:
            ch = chr(av)
            if ch == "\n" or ord(ch) > 127 or (ignore_case and ch in _UNSAFE_FOLD_CHARS):
                flush()
                continue
            current.append(ch)
        elif op == _SUBPATTERN:
            _group, add_flags, del_flags, sub = av
            if add_flags or del_flags:
                # A local (?i:...) / (?-i:...) changes case semantics mid-run.
                raise _Ineligible()
            # Conservatively, a group always ends the run; what it requires
            # on its own is collected separately.
            flush()
            _collect_runs(list(sub), ignore_case, runs)
        elif op in _REPEATS or (_POSSESSIVE is not None and op == _POSSESSIVE):
            lo, _hi, sub = av
            flush()
            if lo >= 1:
                _collect_runs(list(sub), ignore_case, runs)
        elif _ATOMIC is not None and op == _ATOMIC:
            flush()
            _collect_runs(list(av), ignore_case, runs)
        else:
            # BRANCH, IN, ANY, AT, ASSERT, GROUPREF, CATEGORY ...: nothing
            # required across it.
            flush()
    flush()


@dataclass
class PrefilterResult:
    candidates: Dict[str, Set[str]] = field(default_factory=dict)  # rule id -> files
    eligible: Set[str] = field(default_factory=set)
    ineligible: Set[str] = field(default_factory=set)
    literals: Dict[str, Tuple[str, bool]] = field(default_factory=dict)
    rg_calls: int = 0
    elapsed_ms: int = 0

    def rules_for(self, path: str, rules: Sequence[RegexRule]) -> List[RegexRule]:
        """The subset of `rules` Python still needs to run on `path`."""
        return [r for r in rules if r.id not in self.eligible or path in self.candidates.get(r.id, ())]

    def summary(self) -> Dict[str, object]:
        return {
            "eligible_rules": len(self.eligible),
            "ineligible_rules": len(self.ineligible),
            "rg_calls": self.rg_calls,
            "elapsed_ms": self.elapsed_ms,
        }


def build_prefilter(
    root: Path | str,
    paths: Sequence[str],
    rules: Sequence[RegexRule],
    *,
    runner: Optional[RgRunner] = None,
    workers: int = 4,
) -> Optional[PrefilterResult]:
    """Candidate files per eligible rule, or None when rg isn't available."""
    runner = runner or RgRunner(root, allowed_files=paths)
    if not runner.available() or not paths:
        return None
    started = time.monotonic()
    result = PrefilterResult()
    by_literal: Dict[Tuple[str, bool], List[str]] = {}
    for rule in rules:
        lit = required_literal(rule.pattern)
        if lit is None:
            result.ineligible.add(rule.id)
            continue
        result.literals[rule.id] = lit
        by_literal.setdefault(lit, []).append(rule.id)

    def _search(key: Tuple[str, bool]) -> Tuple[Tuple[str, bool], Optional[Set[str]]]:
        literal, icase = key
        res = runner.files_with_matches(
            literal, fixed_strings=True, ignore_case=icase, trusted=True, exhaustive=True,
        )
        if not res.ok or res.timed_out or res.output_truncated:
            return key, None
        return key, set(res.files)

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for key, files in pool.map(_search, list(by_literal)):
            result.rg_calls += 1
            for rule_id in by_literal[key]:
                if files is None:
                    result.ineligible.add(rule_id)
                else:
                    result.eligible.add(rule_id)
                    result.candidates[rule_id] = files
    result.elapsed_ms = int((time.monotonic() - started) * 1000)
    return result


def rules_for_path_fn(
    prefilter: Optional[PrefilterResult], rules: Sequence[RegexRule],
) -> Optional[Callable[[str], List[RegexRule]]]:
    if prefilter is None:
        return None
    return lambda path: prefilter.rules_for(path, rules)
