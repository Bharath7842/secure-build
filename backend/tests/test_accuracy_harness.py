"""Meta-tests for the accuracy harness itself (SAST-00-070): it must fail loudly
and never reach the network."""

import os
import shutil
import socket
import sys
from pathlib import Path

import pytest
import yaml

pytest.importorskip("langgraph")
pytest.importorskip("tree_sitter_java")

from accuracy import runner  # noqa: E402
from accuracy.case import load_case  # noqa: E402

pytestmark = pytest.mark.accuracy

CORPUS = Path(__file__).parent / "accuracy_corpus"


@pytest.fixture()
def case_copy(tmp_path):
    """A throwaway copy of a passing case that a test may damage."""
    def make(case_id="sql-soap-concat"):
        target = tmp_path / case_id
        shutil.copytree(CORPUS / case_id, target)
        return target

    return make


def _edit_yaml(directory: Path, **changes):
    path = directory / "case.yaml"
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw.update(changes)
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")


def test_a_clean_case_passes(case_copy):
    result = runner.run_case(load_case(case_copy()))
    assert result.status == "pass", result.problems


def test_a_missing_recorded_response_fails_with_unrecorded_llm_call(case_copy):
    directory = case_copy()
    shutil.rmtree(directory / "llm_responses")
    result = runner.run_case(load_case(directory))
    assert result.status == "fail"
    assert any("unrecorded LLM call" in problem for problem in result.unrecorded)
    assert "scan_deep_files" in result.unrecorded[0]


def test_a_changed_prompt_is_an_unrecorded_call(case_copy):
    directory = case_copy()
    source = directory / "repo" / "src/main/java/com/acme/dao/SoapDao.java"
    source.write_text(source.read_text() + "\n// a new comment changes the prompt\n")
    result = runner.run_case(load_case(directory))
    assert result.status == "fail" and result.unrecorded


def test_an_expected_finding_that_never_appears_is_named(case_copy):
    directory = case_copy()
    raw = yaml.safe_load((directory / "case.yaml").read_text())
    raw["expected"].append({
        "rule_id": "java-xxe-documentbuilder", "file": "src/main/java/com/acme/dao/SoapDao.java",
        "sink_line": 3, "verdict": "true_positive",
    })
    _edit_yaml(directory, expected=raw["expected"])
    result = runner.run_case(load_case(directory))
    assert result.status == "fail"
    assert any("java-xxe-documentbuilder" in m and "SoapDao.java:3" in m for m in result.missing)


def test_a_verdict_mismatch_is_reported(case_copy):
    directory = case_copy()
    raw = yaml.safe_load((directory / "case.yaml").read_text())
    raw["expected"][0]["verdict"] = "false_positive"
    _edit_yaml(directory, expected=raw["expected"])
    result = runner.run_case(load_case(directory))
    assert result.status == "fail"
    assert any("expected false_positive, got true_positive" in m for m in result.mismatches)


def test_an_unexpected_finding_fails_the_case(case_copy):
    directory = case_copy()
    _edit_yaml(directory, expected=[], allow_absent=True)
    result = runner.run_case(load_case(directory))
    assert result.status == "fail"
    assert any(m.startswith("unexpected finding") for m in result.unexpected)


def test_an_xfail_case_reports_but_does_not_fail(case_copy):
    directory = case_copy()
    raw = yaml.safe_load((directory / "case.yaml").read_text())
    raw["expected"][0]["sink_line"] = 40  # nothing is there
    _edit_yaml(directory, expected=raw["expected"], xfail="EPIC-99")
    result = runner.run_case(load_case(directory))
    assert result.status == "xfail" and result.problems


def test_a_fixed_xfail_case_is_an_xpass(case_copy):
    directory = case_copy()
    _edit_yaml(directory, xfail="EPIC-99")
    assert runner.run_case(load_case(directory)).status == "xpass"


def test_a_replayed_run_never_opens_a_network_socket(case_copy, monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("the accuracy runner opened a network socket")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    assert runner.run_case(load_case(case_copy())).status == "pass"


def test_even_an_unrecorded_call_does_not_reach_the_network(case_copy, monkeypatch):
    directory = case_copy()
    shutil.rmtree(directory / "llm_responses")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("the accuracy runner opened a network socket")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    assert runner.run_case(load_case(directory)).status == "fail"


def test_cloud_credentials_are_removed_for_the_run_and_restored_after(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-example")
    with runner._isolated_environment():
        assert "AWS_ACCESS_KEY_ID" not in os.environ
        assert "OPENAI_API_KEY" not in os.environ
        assert os.environ["AWS_EC2_METADATA_DISABLED"] == "true"
    assert os.environ["AWS_ACCESS_KEY_ID"] == "AKIAEXAMPLE"
    assert os.environ["OPENAI_API_KEY"] == "sk-example"


def test_the_engine_loader_is_restored_after_a_run(case_copy):
    from app.services import agent_bridge

    original = agent_bridge._load_agent_module
    runner.run_case(load_case(case_copy()))
    assert agent_bridge._load_agent_module is original


def test_scripted_recording_reproduces_the_committed_responses(case_copy):
    """The recordings in the repo are exactly what the current prompts and the
    case's scripted answers produce — a stale recording shows up here."""
    directory = case_copy("sql-soap-bound")
    committed = {p.name: p.read_text() for p in (CORPUS / "sql-soap-bound" / "llm_responses").glob("*.json")}
    runner.run_case(load_case(directory), record=runner.RECORD_SCRIPTED)
    rerecorded = {p.name: p.read_text() for p in (directory / "llm_responses").glob("*.json")}
    assert committed and rerecorded == committed


def test_every_committed_case_has_recordings_matching_the_current_prompts():
    from accuracy.case import discover_cases

    for case in discover_cases(CORPUS):
        result = runner.run_case(case)
        assert not result.unrecorded, f"{case.id}: {result.unrecorded}"
