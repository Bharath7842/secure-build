"""The accuracy release gate (SAST-00-100), exercised end to end on a five-case
adjudicated mini corpus: two positives, two negatives and an uncertainty. One test
per gate, plus the baseline rules. In-process, offline, no LLM."""

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest
import yaml

pytest.importorskip("langgraph")
pytest.importorskip("tree_sitter_java")

pytestmark = pytest.mark.accuracy

REPO = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).parent / "fixtures" / "accuracy_gate"

spec = importlib.util.spec_from_file_location("accuracy_gate_cli", REPO / "scripts" / "accuracy" / "gate.py")
cli = importlib.util.module_from_spec(spec)
sys.modules["accuracy_gate_cli"] = cli
spec.loader.exec_module(cli)

POSITIVE, SECOND_POSITIVE = "sql-soap-concat", "log-credential-renamed-logger"
NEGATIVE, SECOND_NEGATIVE = "sql-soap-bound", "xxe-jms-hardened"
UNCERTAIN = "verdict-not-sure"


@pytest.fixture()
def world(tmp_path):
    root = tmp_path / "world"
    shutil.copytree(FIXTURE, root)
    return root


def _run(root: Path, *extra: str):
    out = root / "out"
    code = cli.main([
        "--baseline", str(root / "accuracy_baseline.json"), "--corpus", str(root / "corpus"),
        "--out", str(out), *extra,
    ])
    markdown = (out / "accuracy_gate.md").read_text(encoding="utf-8")
    report = json.loads((out / "accuracy_gate.json").read_text(encoding="utf-8"))
    return code, markdown, report


def _rewrite_response(root: Path, case_id: str, change):
    """Apply `change(findings)` to the recorded model answer of a case."""
    (path,) = list((root / "corpus" / case_id / "llm_responses").glob("*.json"))
    recording = json.loads(path.read_text(encoding="utf-8"))
    answer = json.loads(recording["text"])
    change(answer["findings"])
    recording["text"] = json.dumps(answer)
    path.write_text(json.dumps(recording), encoding="utf-8")


def _edit_case(root: Path, case_id: str, **changes):
    path = root / "corpus" / case_id / "case.yaml"
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw.update(changes)
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")


def _verdict_of(verdict):
    def change(findings):
        for finding in findings:
            finding["verdict"] = verdict
    return change


def _failures(report, gate):
    return report["gates"][str(gate)]["failures"]


# --- clean ------------------------------------------------------------------------

def test_a_clean_run_passes_every_gate(world):
    code, markdown, report = _run(world)
    assert code == 0 and report["passed"] is True
    assert all(g["passed"] for g in report["gates"].values())
    assert "**PASSED**" in markdown and "5 gated case(s)" in markdown
    assert sorted(report["gated"]) == sorted([POSITIVE, SECOND_POSITIVE, NEGATIVE, SECOND_NEGATIVE, UNCERTAIN])


def test_the_markdown_goes_gate_by_gate_then_case_by_case(world):
    _code, markdown, _report = _run(world)
    assert markdown.index("## Gates") < markdown.index("## Cases")
    for number in range(1, 6):
        assert f"| {number}." in markdown
    assert f"`{POSITIVE}`" in markdown


# --- gate 1: preservation ------------------------------------------------------------

def test_a_positive_flipped_to_false_positive_fails_gates_1_and_5(world):
    _rewrite_response(world, POSITIVE, _verdict_of("false_positive"))
    code, markdown, report = _run(world)
    assert code != 0 and report["passed"] is False
    assert any(POSITIVE in f["case"] and "false_positive" in f["message"] for f in _failures(report, 1))
    assert any("true_positive in the baseline, now false_positive" in f["message"] for f in _failures(report, 5))
    assert f"`{POSITIVE}`" in markdown.split("## Failures")[1]
    assert not _failures(report, 2) and not _failures(report, 3)


def test_a_positive_that_vanishes_fails_gate_1_and_5_as_absent(world):
    _rewrite_response(world, POSITIVE, lambda findings: findings.clear())
    code, _markdown, report = _run(world)
    assert code != 0
    assert any("the expected true positive is missing" in f["message"] for f in _failures(report, 1))
    assert any("now absent" in f["message"] for f in _failures(report, 5))


# --- gate 2: negatives ---------------------------------------------------------------

def test_a_negative_with_the_wrong_reason_tag_fails_gate_2(world):
    path = world / "corpus" / NEGATIVE / "case.yaml"
    raw = yaml.safe_load(path.read_text())
    raw["expected"][0]["reason_tag"] = "an-explanation-the-model-never-gave"
    path.write_text(yaml.safe_dump(raw, sort_keys=False))
    code, _markdown, report = _run(world)
    assert code != 0
    assert any("does not mention" in f["message"] for f in _failures(report, 2))


def test_a_negative_that_is_now_a_true_positive_fails_gate_2(world):
    _rewrite_response(world, NEGATIVE, _verdict_of("true_positive"))
    code, _markdown, report = _run(world)
    assert code != 0
    assert any("expected false_positive, got true_positive" in f["message"] for f in _failures(report, 2))


def test_a_negative_that_vanishes_fails_unless_the_case_allows_absent(world):
    _rewrite_response(world, NEGATIVE, lambda findings: findings.clear())
    code, _markdown, report = _run(world)
    assert code != 0
    assert any("the rule stopped firing" in f["message"] for f in _failures(report, 2))

    _edit_case(world, NEGATIVE, allow_absent=True)
    code, _markdown, report = _run(world)
    assert code == 0 and not _failures(report, 2)


# --- gate 3: uncertainty -------------------------------------------------------------

def test_an_uncertain_case_that_resolves_to_true_positive_fails_gate_3(world):
    _rewrite_response(world, UNCERTAIN, _verdict_of("true_positive"))
    code, _markdown, report = _run(world)
    assert code != 0
    assert any("resolved to true_positive instead of staying unverified" in f["message"]
               for f in _failures(report, 3))


def test_an_uncertain_case_with_the_wrong_reason_fails_gate_3(world):
    _rewrite_response(world, UNCERTAIN, _verdict_of(""))  # no verdict at all -> a different reason
    code, _markdown, report = _run(world)
    assert code != 0
    assert any("unresolved_reason is llm_missing_verdict" in f["message"] for f in _failures(report, 3))


# --- gate 4: consistency --------------------------------------------------------------

def test_an_excel_summary_that_miscounts_fails_gate_4(world, monkeypatch):
    from app.services import scan_export

    real_count, real_build = scan_export.count_findings, scan_export.build_excel_report

    def lying(grouped):
        counts = real_count(grouped)
        counts["totals"]["true_positive"]["groups"] += 7
        return counts

    def build_with_lie(project, scan, findings):
        monkeypatch.setattr(scan_export, "count_findings", lying)
        try:
            return real_build(project, scan, findings)
        finally:
            monkeypatch.setattr(scan_export, "count_findings", real_count)

    monkeypatch.setattr(scan_export, "build_excel_report", build_with_lie)
    code, markdown, report = _run(world)
    assert code != 0
    assert _failures(report, 4)
    assert any(f["message"].startswith("Excel summary") for f in _failures(report, 4))
    assert "gate 4" in markdown


# --- gate 5 and the baseline ----------------------------------------------------------

def test_dev_label_only_cases_are_not_gated_but_a_regression_still_fails(world):
    _edit_case(world, POSITIVE, adjudication="dev_label_only")
    _rewrite_response(world, POSITIVE, _verdict_of("false_positive"))
    code, markdown, report = _run(world)
    assert not _failures(report, 1)                    # not adjudicated: gates 1-3 skip it
    assert _failures(report, 5) and code != 0          # but the baseline regression stands
    assert POSITIVE in report["not_gated"]
    assert "## Not gated" in markdown


def test_an_xfail_case_skips_gates_1_to_3_but_not_gate_5(world):
    _edit_case(world, POSITIVE, xfail="EPIC-99")
    _rewrite_response(world, POSITIVE, _verdict_of("false_positive"))
    code, _markdown, report = _run(world)
    assert not _failures(report, 1)
    assert _failures(report, 5) and code != 0
    assert POSITIVE in report["known_gaps"]


def test_without_a_baseline_gate_5_is_skipped_and_said_so(world):
    (world / "accuracy_baseline.json").unlink()
    code, markdown, report = _run(world)
    assert code == 0
    assert any("no baseline" in note for note in report["notes"])
    assert "gate 5 was not evaluated" in markdown


def test_a_case_missing_from_the_baseline_is_a_note_not_a_failure(world):
    baseline = json.loads((world / "accuracy_baseline.json").read_text())
    del baseline["cases"][POSITIVE]
    (world / "accuracy_baseline.json").write_text(json.dumps(baseline))
    code, _markdown, report = _run(world)
    assert code == 0
    assert any(POSITIVE in note and "baseline" in note for note in report["notes"])


def test_update_baseline_is_refused_while_gate_1_fails(world):
    before = (world / "accuracy_baseline.json").read_bytes()
    _rewrite_response(world, POSITIVE, _verdict_of("false_positive"))
    code, _markdown, report = _run(world, "--update-baseline")
    assert code != 0 and report["passed"] is False
    assert (world / "accuracy_baseline.json").read_bytes() == before


def test_update_baseline_is_refused_while_gate_5_fails_even_for_an_xfail_case(world):
    before = (world / "accuracy_baseline.json").read_bytes()
    _edit_case(world, POSITIVE, xfail="EPIC-99")
    _rewrite_response(world, POSITIVE, _verdict_of("false_positive"))
    code, _markdown, report = _run(world, "--update-baseline")
    assert code != 0 and not _failures(report, 1) and _failures(report, 5)
    assert (world / "accuracy_baseline.json").read_bytes() == before


def test_update_baseline_rewrites_it_when_the_gates_allow(world):
    (world / "accuracy_baseline.json").write_text(json.dumps({"version": 1, "cases": {}}))
    code, _markdown, _report = _run(world, "--update-baseline")
    assert code == 0
    rewritten = json.loads((world / "accuracy_baseline.json").read_text())
    assert set(rewritten["cases"]) == {POSITIVE, SECOND_POSITIVE, NEGATIVE, SECOND_NEGATIVE, UNCERTAIN}
    assert rewritten["cases"][POSITIVE]["findings"][0]["verdict"] == "true_positive"
    # ... and a second, plain run against the new baseline is clean.
    assert _run(world)[0] == 0


# --- no live calls ----------------------------------------------------------------------

def test_a_prompt_change_fails_with_unrecorded_llm_call_not_a_live_call(world, monkeypatch):
    import socket

    def forbidden(*_a, **_k):
        raise AssertionError("the gate opened a network socket")

    monkeypatch.setattr(socket, "socket", forbidden)
    shutil.rmtree(world / "corpus" / POSITIVE / "llm_responses")
    code, _markdown, report = _run(world)
    assert code != 0
    assert any("unrecorded LLM call" in f["message"] for f in _failures(report, 1))


def test_an_empty_corpus_is_an_error_not_a_pass(tmp_path):
    (tmp_path / "corpus").mkdir()
    assert cli.main(["--baseline", str(tmp_path / "b.json"), "--corpus", str(tmp_path / "corpus"),
                     "--out", str(tmp_path / "out")]) == 2
