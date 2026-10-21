"""The verdict / issue-class / unresolved-reason contract (SAST-00-010).

`app/models.py` and the engine each hold a copy of the enum sets (the engine
cannot import `app`); these tests keep them equal and check the engine-side
write paths that must say why a finding is `unverified`.
"""

import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("langgraph")

from app import models  # noqa: E402
from app.config import settings  # noqa: E402
from app.services.agent_bridge import _load_agent_module  # noqa: E402

_ENGINE_DIR = Path(__file__).resolve().parents[1] / "sast_engine"
_RULES_DIR = _ENGINE_DIR / "rules"


@pytest.fixture()
def agent(monkeypatch):
    monkeypatch.setattr(settings, "sast_framework_path", str(_ENGINE_DIR))
    sys.modules.pop("sast_scan_agent", None)
    return _load_agent_module()


@pytest.fixture()
def llm_file_scan(agent):
    return sys.modules["pipeline.llm_file_scan"]


@pytest.fixture()
def regex_scan(agent):
    return sys.modules["pipeline.regex_scan"]


@pytest.fixture()
def rules(regex_scan):
    return regex_scan.load_rules(_RULES_DIR)


def test_engine_and_app_enum_sets_match(llm_file_scan):
    assert llm_file_scan.VERDICTS == models.VERDICTS
    assert llm_file_scan.ISSUE_CLASSES == models.ISSUE_CLASSES
    assert llm_file_scan.UNRESOLVED_REASONS == models.UNRESOLVED_REASONS


def test_the_contract_contains_every_required_reason():
    required = {
        "not_reviewed_regex", "llm_missing_verdict", "llm_unrecognised_verdict",
        "llm_call_failed", "llm_budget_exhausted", "cap_reached", "evidence_missing",
    }
    assert required <= models.UNRESOLVED_REASONS


# --- rule catalog -----------------------------------------------------------

def test_every_shipped_rule_declares_a_known_issue_class(regex_scan):
    for rule in regex_scan.load_rules(_RULES_DIR):
        assert rule.issue_class in models.ISSUE_CLASSES, rule.id


def test_only_the_two_documented_rules_are_quality(regex_scan):
    quality = {r.id for r in regex_scan.load_rules(_RULES_DIR) if r.issue_class == "quality"}
    assert quality == {"serializable-missing-svuid", "logger-exception-tostring"}


def test_a_rule_with_an_unknown_issue_class_is_flagged_by_the_loader_contract(regex_scan):
    # RegexRule keeps what the JSON says; the catalog test is what rejects it.
    rule = regex_scan.RegexRule({"id": "x", "pattern": "x", "issue_class": "bogus"})
    assert rule.issue_class not in models.ISSUE_CLASSES


def test_json_catalog_files_only_use_known_issue_classes():
    for path in _RULES_DIR.glob("*.json"):
        if path.name == "surfaces.json":
            continue
        for raw in json.loads(path.read_text(encoding="utf-8")):
            assert raw.get("issue_class", "security") in models.ISSUE_CLASSES, raw["id"]


# --- regex findings ---------------------------------------------------------

def _hits_for(regex_scan, llm_file_scan, rules, text, *, path="A.java"):
    scanned = regex_scan.scan_text(text, rules, file_lang=llm_file_scan.lang_for_path(path))
    return llm_file_scan.findings_from_hits(
        file_path=path, source_text=text, hits=scanned,
        rules_by_id={r.id: r for r in rules},
    )


def test_regex_findings_are_unverified_not_reviewed_with_their_rule_class(
    regex_scan, llm_file_scan, rules
):
    text = "public class Foo implements Serializable {\n}\n"
    findings = _hits_for(regex_scan, llm_file_scan, rules, text)
    svuid = [f for f in findings if f["rule_id"] == "serializable-missing-svuid"]
    assert svuid
    for finding in svuid:
        assert finding["verdict"] == "unverified"
        assert finding["unresolved_reason"] == "not_reviewed_regex"
        assert finding["issue_class"] == "quality"


def test_a_default_rule_is_a_security_issue(regex_scan, llm_file_scan, rules):
    findings = _hits_for(
        regex_scan, llm_file_scan, rules, "password = 'hunter2'\n", path="a.py"
    )
    assert findings
    assert {f["issue_class"] for f in findings if f["rule_id"] == "secret-password-assign"} == {
        "security"
    }


def test_a_two_rule_mini_catalog_carries_issue_class_per_rule(regex_scan, llm_file_scan):
    mini = [
        regex_scan.RegexRule({"id": "sec", "pattern": "needle", "cwe": "CWE-1"}),
        regex_scan.RegexRule(
            {"id": "qual", "pattern": "haystack", "cwe": "CWE-2", "issue_class": "quality"}
        ),
    ]
    findings = _hits_for(regex_scan, llm_file_scan, mini, "needle\nhaystack\n", path="a.txt")
    assert {f["rule_id"]: f["issue_class"] for f in findings} == {
        "sec": "security", "qual": "quality",
    }


# --- budget exhaustion ------------------------------------------------------

@pytest.fixture()
def _budget_exhausted(llm_file_scan):
    # The class the engine itself checks (llm_client can be re-imported between
    # fixtures, which would give a different class object).
    def raise_budget(*_args, **_kwargs):
        raise llm_file_scan.LlmBudgetExhausted("stage budget share reached")

    return raise_budget


def test_deep_scan_budget_exhaustion_leaves_regex_hits_unresolved(
    tmp_path, llm_file_scan, rules, _budget_exhausted
):
    (tmp_path / "a.py").write_text("password = 'hunter2'\n", encoding="utf-8")

    result = llm_file_scan.scan_file(
        repo_root=tmp_path, rel_path="a.py", rules=rules,
        call_llm_fn=_budget_exhausted, chunk_workers=1,
    )

    assert result["chunk_errors"]
    assert result["unverified_count"] >= 1
    assert result["fp_count"] == 0
    hit = next(f for f in result["findings"] if f["rule_id"] == "secret-password-assign")
    assert hit["verdict"] == "unverified"
    assert hit["unresolved_reason"] == "llm_budget_exhausted"
    assert hit["kind"] == "regex"
    assert hit["file_path"] == "a.py"


def test_a_failed_deep_scan_call_that_is_not_the_budget_writes_nothing_extra(
    tmp_path, llm_file_scan, rules
):
    (tmp_path / "a.py").write_text("password = 'hunter2'\n", encoding="utf-8")

    def broken(*_args, **_kwargs):
        raise RuntimeError("provider unavailable")

    result = llm_file_scan.scan_file(
        repo_root=tmp_path, rel_path="a.py", rules=rules,
        call_llm_fn=broken, chunk_workers=1,
    )
    assert result["findings"] == []
    assert result["unverified_count"] == 0
    assert result["chunk_errors"]


# --- triage and group confirm -----------------------------------------------

def _unverified(file_path, *, severity="MEDIUM"):
    return {
        "rule_id": "secret-password-assign", "title": "hardcoded password",
        "severity": severity, "cwe": "CWE-798",
        "owasp_category": "A07:2021-Identification-and-Authentication-Failures",
        "line": 1, "snippet": "password = 'hunter2'", "matched_text": "password = 'hunter2'",
        "verdict": "unverified", "unresolved_reason": "not_reviewed_regex",
        "kind": "regex", "confidence": None, "file_path": file_path,
    }


def test_group_confirm_call_failure_is_recorded_as_llm_call_failed(
    tmp_path, llm_file_scan, rules
):
    (tmp_path / "a.py").write_text("password = 'hunter2'\n", encoding="utf-8")
    results = [{"file_path": "a.py", "findings": [_unverified("a.py")]}]
    written = []

    def broken(*_a, **_k):
        raise RuntimeError("provider unavailable")

    llm_file_scan.group_confirm_unverified_findings(
        file_results=results, repo_root=tmp_path, rules=rules, call_llm_fn=broken,
        group_workers=1, verdict_updates_writer=lambda path, ups: written.append((path, ups)),
    )

    finding = results[0]["findings"][0]
    assert finding["verdict"] == "unverified"
    assert finding["unresolved_reason"] == "llm_call_failed"
    (_path, updates), = written
    assert updates == [{"rule_id": "secret-password-assign", "line": 1,
                        "unresolved_reason": "llm_call_failed"}]


def test_group_confirm_budget_exhaustion_is_recorded_as_such(
    tmp_path, llm_file_scan, rules, _budget_exhausted
):
    (tmp_path / "a.py").write_text("password = 'hunter2'\n", encoding="utf-8")
    results = [{"file_path": "a.py", "findings": [_unverified("a.py")]}]

    llm_file_scan.group_confirm_unverified_findings(
        file_results=results, repo_root=tmp_path, rules=rules,
        call_llm_fn=_budget_exhausted, group_workers=1,
    )
    assert results[0]["findings"][0]["unresolved_reason"] == "llm_budget_exhausted"


def test_group_confirm_missing_verdict_is_recorded(tmp_path, llm_file_scan, rules):
    (tmp_path / "a.py").write_text("password = 'hunter2'\n", encoding="utf-8")
    results = [{"file_path": "a.py", "findings": [_unverified("a.py")]}]

    llm_file_scan.group_confirm_unverified_findings(
        file_results=results, repo_root=tmp_path, rules=rules, group_workers=1,
        call_llm_fn=lambda *a, **k: '{"decisions": [{"confidence": 0.5}]}',
    )
    assert results[0]["findings"][0]["verdict"] == "unverified"
    assert results[0]["findings"][0]["unresolved_reason"] == "llm_missing_verdict"


def test_groups_past_the_cap_are_marked_cap_reached(tmp_path, llm_file_scan, rules):
    for name in ("a.py", "b.py"):
        (tmp_path / name).write_text("password = 'hunter2'\nx = 1\n", encoding="utf-8")
    second = _unverified("b.py")
    second["matched_text"] = "x = 1"  # a different construct, so a different group
    results = [
        {"file_path": "a.py", "findings": [_unverified("a.py"), _unverified("a.py")]},
        {"file_path": "b.py", "findings": [second]},
    ]
    written = []

    llm_file_scan.group_confirm_unverified_findings(
        file_results=results, repo_root=tmp_path, rules=rules, group_workers=1,
        group_cap=1, verdict_updates_writer=lambda p, u: written.append((p, u)),
        call_llm_fn=lambda *a, **k: (
            '{"decisions": [{"verdict": "true_positive", "confidence": 0.9,'
            ' "verdict_reason": "real"}]}'
        ),
    )

    assert results[1]["findings"][0]["unresolved_reason"] == "cap_reached"
    assert all(f["unresolved_reason"] is None for f in results[0]["findings"])
    capped = [u for p, ups in written for u in ups if u.get("unresolved_reason") == "cap_reached"]
    assert len(capped) == 1


def test_a_confirmed_group_clears_the_reason(tmp_path, llm_file_scan, rules):
    (tmp_path / "a.py").write_text("password = 'hunter2'\n", encoding="utf-8")
    results = [{"file_path": "a.py", "findings": [_unverified("a.py")]}]
    llm_file_scan.group_confirm_unverified_findings(
        file_results=results, repo_root=tmp_path, rules=rules, group_workers=1,
        call_llm_fn=lambda *a, **k: (
            '{"decisions": [{"verdict": "false_positive", "confidence": 0.1,'
            ' "verdict_reason": "fixture"}]}'
        ),
    )
    finding = results[0]["findings"][0]
    assert finding["verdict"] == "false_positive"
    assert finding["unresolved_reason"] is None


def test_triage_call_failure_and_missing_decisions_are_told_apart(
    tmp_path, llm_file_scan, rules, _budget_exhausted
):
    text = "password = 'hunter2'\n"
    hits = [{"line": 1, "rule": "secret-password-assign", "category": "secrets",
             "severity": "HIGH", "matched_text": "password = 'hunter2'"}]

    def call(fn):
        return llm_file_scan.triage_regex_hits(
            file_path="a.py", source_text=text, hits=hits, rules=rules, call_llm_fn=fn,
        )

    missing = call(lambda *a, **k: '{"decisions": []}')
    assert [f["unresolved_reason"] for f in missing["findings"]] == ["llm_missing_verdict"]

    budget = call(_budget_exhausted)
    assert [f["unresolved_reason"] for f in budget["findings"]] == ["llm_budget_exhausted"]

    def broken(*_a, **_k):
        raise RuntimeError("down")

    failed = call(broken)
    assert [f["unresolved_reason"] for f in failed["findings"]] == ["llm_call_failed"]
