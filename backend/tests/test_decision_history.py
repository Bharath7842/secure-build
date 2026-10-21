"""The append-only machine decision history of a finding (SAST-00-050)."""

import inspect
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import db as db_module
from app.config import settings
from app.db import init_db
from app.main import app
from app.models import AppendOnlyError, Finding, FindingDecision, Project, Scan
from app.services import agent_bridge, decisions, git_workspace, scan_runner
from app.services.scan_runner import (
    _make_findings_writer,
    _make_reachability_updates_writer,
    _make_verdict_updates_writer,
)

from tests.auth_helpers import ADMIN_HEADERS, make_user
from tests.test_scan_runner_reconcile import (
    _disable_mock_engine,
    _make_fake_agent,
)

pytestmark = pytest.mark.integration

VERSIONS = {"engine_commit": "abc123", "rule_catalog_sha256": "r" * 64, "result_cache_version": "2"}


@pytest.fixture()
def SessionLocal(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    settings.use_mock_engine = True
    settings.scan_logs_dir = str(tmp_path / "scan_logs")
    init_db(f"sqlite:///{(tmp_path / 'decisions.db').as_posix()}")
    return db_module.SessionLocal


def _seed_scan(SessionLocal, scan_id="s1", project_id="p1", versions=VERSIONS):
    with SessionLocal() as db:
        db.add(Project(id=project_id, name=f"proj-{project_id}", default_git_url="https://example.com/r.git"))
        db.add(Scan(
            id=scan_id, project_id=project_id, git_url="https://example.com/r.git", branch="main",
            commit_sha="abc", status="running", version=1, llm_provider="bedrock", llm_model="haiku",
            metadata_json={"use_llm": True, "versions": dict(versions)},
        ))
        db.commit()


def _regex_finding(**overrides) -> dict:
    finding = {
        "verdict": "unverified", "unresolved_reason": "not_reviewed_regex", "issue_class": "security",
        "severity": "MEDIUM", "cwe": "CWE-798", "rule_id": "secret-password-assign",
        "title": "hardcoded password", "file_path": "app/config.py", "line": 5,
        "snippet": "password = 'x'", "matched_text": "password = 'x'", "kind": "regex",
        "confidence": None, "verdict_reason": "regex match, not reviewed",
    }
    finding.update(overrides)
    return finding


def _rows(SessionLocal, finding_id=None, scan_id="s1"):
    with SessionLocal() as db:
        query = db.query(FindingDecision).filter(FindingDecision.scan_id == scan_id)
        if finding_id:
            query = query.filter(FindingDecision.finding_id == finding_id)
        return query.order_by(FindingDecision.at, FindingDecision.id).all()


def _only_finding(SessionLocal, scan_id="s1") -> Finding:
    with SessionLocal() as db:
        return db.query(Finding).filter(Finding.scan_id == scan_id).one()


def _confirm(scan_id="s1", **update):
    update = {"rule_id": "secret-password-assign", "line": 5, "verdict": "true_positive",
              "confidence": 0.9, "verdict_reason": "real", "ai_fix": "use env", **update}
    _make_verdict_updates_writer(scan_id)("app/config.py", [update])


# --- the chain ----------------------------------------------------------------

def test_a_regex_finding_later_confirmed_has_exactly_two_decisions(SessionLocal):
    _seed_scan(SessionLocal)
    _make_findings_writer("s1")("app/config.py", [_regex_finding()])
    _confirm()

    finding = _only_finding(SessionLocal)
    rows = _rows(SessionLocal, finding.id)
    assert [(r.stage, r.verdict, r.confidence) for r in rows] == [
        ("triage_regex", "unverified", None), ("group_confirm", "true_positive", 0.9),
    ]
    assert rows[0].unresolved_reason == "not_reviewed_regex"
    assert rows[1].unresolved_reason is None
    assert finding.verdict == rows[-1].verdict == "true_positive"
    assert rows[0].occurrence_id == finding.occurrence_id and finding.occurrence_id


def test_the_evidence_version_carries_the_scans_versions_and_the_cache_flag(SessionLocal):
    _seed_scan(SessionLocal)
    _make_findings_writer("s1")("app/config.py", [_regex_finding()])
    _confirm(result_cache_hit=True)

    first, second = _rows(SessionLocal)
    assert first.evidence_version == {**VERSIONS, "result_cache_hit": False}
    assert second.evidence_version == {**VERSIONS, "result_cache_hit": True}


def test_the_initial_stage_follows_the_engines_stamp_or_the_kind(SessionLocal):
    _seed_scan(SessionLocal)
    _make_findings_writer("s1")("a.py", [
        _regex_finding(line=1, kind="llm", verdict="true_positive", unresolved_reason=None),
        _regex_finding(line=2, kind="flow", verdict="false_positive", unresolved_reason=None),
        _regex_finding(line=3, kind="joern"),
        _regex_finding(line=4, kind="sca"),
        _regex_finding(line=5, decision_stage="triage_llm", verdict="false_positive",
                       unresolved_reason=None),
        _regex_finding(line=6, decision_stage="not-a-stage"),
    ])
    with SessionLocal() as db:
        stages = {
            f.line: db.query(FindingDecision).filter(FindingDecision.finding_id == f.id).one().stage
            for f in db.query(Finding).all()
        }
    assert stages == {1: "deep_scan", 2: "flow_verify", 3: "joern_confirm", 4: "sca_match",
                      5: "triage_llm", 6: "triage_regex"}


def test_an_update_that_changes_nothing_appends_nothing(SessionLocal):
    _seed_scan(SessionLocal)
    _make_findings_writer("s1")("app/config.py", [_regex_finding()])
    _confirm()
    _confirm()  # same verdict, same confidence

    assert len(_rows(SessionLocal)) == 2


def test_a_confidence_change_with_the_same_verdict_is_a_decision(SessionLocal):
    _seed_scan(SessionLocal)
    _make_findings_writer("s1")("app/config.py", [_regex_finding()])
    _confirm(confidence=0.7)
    _confirm(confidence=0.95)

    assert [r.confidence for r in _rows(SessionLocal)] == [None, 0.7, 0.95]


def test_an_undecided_reason_update_is_not_a_decision(SessionLocal):
    _seed_scan(SessionLocal)
    _make_findings_writer("s1")("app/config.py", [_regex_finding()])
    _make_verdict_updates_writer("s1")("app/config.py", [
        {"rule_id": "secret-password-assign", "line": 5, "unresolved_reason": "llm_call_failed"},
    ])

    assert len(_rows(SessionLocal)) == 1
    assert _only_finding(SessionLocal).unresolved_reason == "llm_call_failed"


def test_a_joern_confirm_update_is_stamped_joern_confirm(SessionLocal):
    _seed_scan(SessionLocal)
    _make_findings_writer("s1")("app/config.py", [_regex_finding(kind="joern")])
    _confirm(decision_stage="joern_confirm")

    assert [r.stage for r in _rows(SessionLocal)] == ["joern_confirm", "joern_confirm"]


def test_the_reachability_floor_is_a_decision_only_when_it_raises_confidence(SessionLocal):
    _seed_scan(SessionLocal)
    _make_findings_writer("s1")("app/config.py", [
        _regex_finding(verdict="true_positive", unresolved_reason=None, confidence=0.5, kind="llm"),
    ])
    writer = _make_reachability_updates_writer("s1")
    evidence = {"status": "path", "sink_kind": "sql"}

    writer("app/config.py", [{"rule_id": "secret-password-assign", "line": 5,
                              "reachability": evidence, "confidence": 0.5}])
    assert len(_rows(SessionLocal)) == 1  # evidence attached, confidence unchanged

    writer("app/config.py", [{"rule_id": "secret-password-assign", "line": 5,
                              "reachability": evidence, "confidence": 0.9}])
    rows = _rows(SessionLocal)
    assert [(r.stage, r.confidence) for r in rows] == [("deep_scan", 0.5), ("reachability_floor", 0.9)]
    assert rows[-1].verdict == "true_positive"
    assert _only_finding(SessionLocal).reachability == evidence


def test_the_reconcile_sweep_appends_a_reconcile_decision(SessionLocal, monkeypatch, tmp_path):
    _disable_mock_engine(monkeypatch)
    _seed_scan(SessionLocal)
    _make_findings_writer("s1")("src/App.java", [_regex_finding(file_path="src/App.java", line=10)])
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(git_workspace, "ensure_workspace", lambda *a, **k: workspace)
    monkeypatch.setattr(agent_bridge, "_load_agent_module", lambda: _make_fake_agent())

    scan_runner.reconcile_unverified_findings("s1")

    rows = _rows(SessionLocal)
    assert [(r.stage, r.verdict) for r in rows] == [
        ("triage_regex", "unverified"), ("reconcile", "true_positive"),
    ]


def test_finding_verdict_always_equals_its_latest_decision(SessionLocal):
    _seed_scan(SessionLocal)
    _make_findings_writer("s1")("app/config.py", [
        _regex_finding(line=1),
        _regex_finding(line=2, verdict="true_positive", unresolved_reason=None, confidence=0.6, kind="llm"),
        _regex_finding(line=3, verdict="false_positive", unresolved_reason=None, confidence=0.3, kind="llm"),
    ])
    for line, verdict in ((1, "false_positive"), (2, "true_positive"), (3, "true_positive")):
        _make_verdict_updates_writer("s1")("app/config.py", [{
            "rule_id": "secret-password-assign", "line": line, "verdict": verdict,
            "confidence": 0.8, "verdict_reason": "x",
        }])

    with SessionLocal() as db:
        for finding in db.query(Finding).filter(Finding.scan_id == "s1"):
            latest = (
                db.query(FindingDecision).filter(FindingDecision.finding_id == finding.id)
                .order_by(FindingDecision.at.desc(), FindingDecision.id.desc()).first()
            )
            assert (finding.verdict, finding.confidence) == (latest.verdict, latest.confidence), finding.line


# --- append-only --------------------------------------------------------------

def test_the_decisions_module_exposes_inserts_only():
    names = {n for n, f in inspect.getmembers(decisions, inspect.isfunction) if f.__module__ == decisions.__name__}
    assert names == {"stage_for_new_finding", "evidence_version", "record_initial", "record_change", "_decision"}
    assert not [n for n in names if n.lstrip("_").startswith(("update", "delete", "remove", "edit", "set"))]


def test_the_orm_refuses_to_update_or_delete_a_decision(SessionLocal):
    _seed_scan(SessionLocal)
    _make_findings_writer("s1")("app/config.py", [_regex_finding()])
    with SessionLocal() as db:
        row = db.query(FindingDecision).one()
        row.verdict = "false_positive"
        with pytest.raises(AppendOnlyError):
            db.flush()
        db.rollback()
        db.delete(db.query(FindingDecision).one())
        with pytest.raises(AppendOnlyError):
            db.flush()
        db.rollback()
    assert _rows(SessionLocal)[0].verdict == "unverified"


def test_deleting_the_scans_findings_cascades_to_their_decisions(SessionLocal):
    _seed_scan(SessionLocal)
    _make_findings_writer("s1")("app/config.py", [_regex_finding()])
    _confirm()
    assert len(_rows(SessionLocal)) == 2
    with SessionLocal() as db:
        db.query(Finding).filter(Finding.scan_id == "s1").delete(synchronize_session=False)
        db.commit()
    assert _rows(SessionLocal) == []


# --- the history endpoint -----------------------------------------------------

@pytest.fixture()
def client(SessionLocal):
    return TestClient(app)


def _history(client, scan_id, finding_id, headers=ADMIN_HEADERS):
    return client.get(f"/scans/{scan_id}/findings/{finding_id}/history", headers=headers)


def test_the_history_merges_a_human_override_after_the_machine_rows(client, SessionLocal):
    _seed_scan(SessionLocal)
    _make_findings_writer("s1")("app/config.py", [_regex_finding()])
    _confirm()
    finding = _only_finding(SessionLocal)
    reviewer = make_user("reviewer@test.local", role="admin")[1]
    resp = client.post(
        f"/scans/s1/findings/{finding.id}/review", headers=reviewer,
        json={"decision": "false_positive", "comment": "it is a fixture"},
    )
    assert resp.status_code == 200, resp.text

    body = _history(client, "s1", finding.id).json()
    entries = body["entries"]
    assert [(e["source"], e["actor"]) for e in entries][:2] == [
        ("machine", "triage_regex"), ("machine", "group_confirm"),
    ]
    assert entries[-1]["source"] == "human"
    assert entries[-1]["actor"] == "reviewer@test.local"
    assert entries[-1]["to_verdict"] == "false_positive"
    machine = [e for e in entries if e["source"] == "machine"]
    assert [(e["from_verdict"], e["to_verdict"]) for e in machine] == [
        (None, "unverified"), ("unverified", "true_positive"),
    ]
    assert machine[0]["evidence_version"]["engine_commit"] == "abc123"
    times = [e["at"] for e in entries]
    assert times == sorted(times)


def test_the_history_of_an_unknown_finding_is_404(client, SessionLocal):
    _seed_scan(SessionLocal)
    assert _history(client, "s1", "nope").status_code == 404


def test_a_finding_of_another_scan_is_404(client, SessionLocal):
    _seed_scan(SessionLocal)
    _seed_scan(SessionLocal, scan_id="s2", project_id="p2")
    _make_findings_writer("s2")("app/config.py", [_regex_finding()])
    other = _only_finding(SessionLocal, "s2")
    assert _history(client, "s1", other.id).status_code == 404


def test_anonymous_gets_401_and_another_users_scan_is_404(client, SessionLocal):
    _seed_scan(SessionLocal)
    _make_findings_writer("s1")("app/config.py", [_regex_finding()])
    finding = _only_finding(SessionLocal)
    assert client.get(f"/scans/s1/findings/{finding.id}/history").status_code == 401
    _, bob = make_user("bob@test.local")
    assert _history(client, "s1", finding.id, headers=bob).status_code == 404


# --- the engine's stamps ------------------------------------------------------

_ENGINE_DIR = Path(__file__).resolve().parents[1] / "sast_engine"


@pytest.fixture()
def engine(monkeypatch):
    pytest.importorskip("langgraph")
    monkeypatch.setattr(settings, "sast_framework_path", str(_ENGINE_DIR))
    sys.modules.pop("sast_scan_agent", None)
    agent_bridge._load_agent_module()
    return sys.modules["llm_client"], sys.modules["pipeline.llm_file_scan"], sys.modules["pipeline.regex_scan"]


def test_the_engine_stamps_each_finding_with_the_stage_that_decided_it(engine):
    _client, lfs, regex_scan = engine
    llm = lfs.normalize_finding({"line": 1, "verdict": "true_positive", "cwe": "CWE-1", "title": "t"},
                                file_path="a.py", chunk_start=1, chunk_end=3)
    flow = lfs.normalize_finding({"line": 1, "verdict": "true_positive", "cwe": "CWE-1", "title": "t"},
                                 file_path="a.py", chunk_start=1, chunk_end=3, kind="flow")
    rules = regex_scan.load_rules(_ENGINE_DIR / "rules")
    hits = [{"rule": "secret-password-assign", "line": 1, "matched_text": "password = 'a'", "severity": "HIGH"}]
    regex = lfs.findings_from_hits(file_path="a.py", source_text="password = 'a'\n", hits=hits,
                                   rules_by_id={r.id: r for r in rules})
    assert (llm["decision_stage"], flow["decision_stage"], regex[0]["decision_stage"]) == (
        "deep_scan", "flow_verify", "triage_regex")


def test_call_llm_reports_whether_the_last_answer_was_replayed(engine):
    llm_client, _lfs, _rs = engine

    class Cache:
        def __init__(self, hit):
            self.hit = hit

        def get(self, key):
            return {"text": '{"findings": []}', "input_tokens": 1, "output_tokens": 1} if self.hit else None

        def put(self, key, **_kw):
            pass

    def live(system, user, model_id, max_tokens, temperature, retries, *, meta_out=None, **_kw):
        meta_out.update({"input_tokens": 1, "output_tokens": 1})
        return '{"findings": []}'

    llm_client._call_bedrock = live
    replayed = llm_client.call_llm(
        "s", "u", usage={llm_client.RESULT_CACHE_USAGE_KEY: Cache(True)}, step="x",
        provider="bedrock", model="m", json_mode=True,
    )
    assert replayed and llm_client.last_call_was_cache_hit() is True
    llm_client.call_llm(
        "s", "u", usage={llm_client.RESULT_CACHE_USAGE_KEY: Cache(False)}, step="x",
        provider="bedrock", model="m", json_mode=True,
    )
    assert llm_client.last_call_was_cache_hit() is False


def test_a_replayed_deep_scan_answer_is_flagged_on_its_findings(engine):
    llm_client, lfs, _rs = engine

    class Hit:
        def get(self, key):
            return {"text": '{"findings": [{"line": 1, "verdict": "true_positive", "cwe": "CWE-1", '
                            '"title": "t", "rule_id": "llm-extra", "severity": "HIGH"}]}',
                    "input_tokens": 1, "output_tokens": 1}

        def put(self, key, **_kw):
            pass

    result = lfs.scan_chunk(
        file_path="a.py", chunk={"start_line": 1, "end_line": 3, "text": "x\ny\nz\n"},
        catalog=[], stack_context="", usage={llm_client.RESULT_CACHE_USAGE_KEY: Hit()},
        llm_provider="bedrock", llm_model="m", call_llm_fn=llm_client.call_llm,
    )
    assert [f["result_cache_hit"] for f in result["findings"]] == [True]


# --- observability --------------------------------------------------------------

def test_decision_counts_by_stage_land_in_the_usage_summary(SessionLocal, monkeypatch):
    _seed_scan(SessionLocal)
    _make_findings_writer("s1")("app/config.py", [_regex_finding(), _regex_finding(line=9)])
    _confirm()
    lines = []
    monkeypatch.setattr(scan_runner.scan_log, "log", lambda _id, line: lines.append(line))

    scan_runner._record_decision_counts("s1")

    with SessionLocal() as db:
        summary = db.get(Scan, "s1").metadata_json["usage_summary"]
    assert summary["decisions_by_stage"] == {"triage_regex": 2, "group_confirm": 1}
    assert lines == ["Decision history rows by stage: group_confirm=1, triage_regex=2."]
