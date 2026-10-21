"""The accuracy corpus: every case scanned with the real graph, offline, against
its recorded LLM responses (SAST-00-070). Run with `pytest -m accuracy`.

Each case reports pass/fail, missing expected findings, unexpected findings and
verdict mismatches. A case marked `xfail` in its case.yaml (a known gap, naming
the epic that will fix it) reports but does not fail the run, and fails the run
the day it starts passing, so the marker is removed with the fix. A call with no
recording fails the case with "unrecorded LLM call" — it never goes live.

Recording is deliberate and manual: `ACCURACY_RECORD=scripted pytest -m accuracy`
rewrites every case's recordings from its `scripted:` answers (no network), and
`ACCURACY_RECORD=live` does it with the real provider (this spends money).
"""

import json
import os
from pathlib import Path

import pytest

pytest.importorskip("langgraph")
pytest.importorskip("tree_sitter_java")

from accuracy.case import discover_cases  # noqa: E402
from accuracy.runner import run_case, summarize  # noqa: E402

pytestmark = pytest.mark.accuracy

CORPUS = Path(__file__).parent / "accuracy_corpus"
CASES = discover_cases(CORPUS)
REPORT_PATH = Path(os.environ.get("ACCURACY_REPORT", Path(__file__).resolve().parents[1] / "accuracy_report.json"))

RECORD = os.environ.get("ACCURACY_RECORD") or None
if RECORD not in (None, "scripted", "live"):
    raise pytest.UsageError(f"ACCURACY_RECORD must be 'scripted' or 'live', not {RECORD!r}")

_results: list = []


@pytest.fixture(scope="module", autouse=True)
def _write_report():
    yield
    if _results:
        REPORT_PATH.write_text(json.dumps(summarize(_results), indent=2) + "\n", encoding="utf-8")


def test_the_corpus_is_not_empty_and_covers_every_seed_pair():
    ids = {case.id for case in CASES}
    assert {
        "sql-soap-concat", "sql-soap-bound", "log-credential", "log-credential-renamed-logger",
        "xxe-jms-unhardened", "xxe-jms-hardened", "group-mixed-member", "verdict-not-sure",
    } <= ids


@pytest.mark.parametrize("case", CASES, ids=[case.id for case in CASES])
def test_case(case):
    result = run_case(case, record=RECORD)
    _results.append(result)
    detail = "\n  ".join(result.problems)
    if result.status == "xfail":
        pytest.xfail(f"known gap, fixed by {case.xfail}:\n  {detail}")
    if result.status == "xpass":
        pytest.fail(f"{case.id} now passes: remove `xfail: {case.xfail}` from its case.yaml")
    assert result.status == "pass", f"{case.id} failed:\n  {detail}"
