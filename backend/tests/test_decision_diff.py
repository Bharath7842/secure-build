"""The rescan decision diff (SAST-00-090): per-occurrence, both directions,
joined on `occurrence_id` only."""

import sys
from io import BytesIO
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from openpyxl import load_workbook

pytest.importorskip("langgraph")
pytest.importorskip("tree_sitter_java")

from app import db as db_module  # noqa: E402
from app.config import settings  # noqa: E402
from app.db import init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Finding, Project, Scan  # noqa: E402
from app.services import decision_diff as dd  # noqa: E402
from app.services.agent_bridge import _load_agent_module  # noqa: E402
from app.services.scan_runner import _make_findings_writer, _make_verdict_updates_writer  # noqa: E402

from tests.auth_helpers import ADMIN_HEADERS, make_user  # noqa: E402

pytestmark = pytest.mark.integration

_ENGINE_DIR = Path(__file__).resolve().parents[1] / "sast_engine"
_FIXTURES = Path(__file__).parent / "fixtures" / "identity"
ORDERS = "Orders.java"


@pytest.fixture()
def occurrence(monkeypatch):
    monkeypatch.setattr(settings, "sast_framework_path", str(_ENGINE_DIR))
    sys.modules.pop("sast_scan_agent", None)
    _load_agent_module()
    return sys.modules["pipeline.occurrence"]


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    settings.use_mock_engine = True
    settings.scan_logs_dir = str(tmp_path / "scan_logs")
    init_db(f"sqlite:///{(tmp_path / 'diff.db').as_posix()}")
    return TestClient(app)


def _project(project_id="p1"):
    with db_module.SessionLocal() as db:
        if db.get(Project, project_id) is None:
            db.add(Project(id=project_id, name=f"proj-{project_id}", default_git_url="https://example.com/r.git"))
            db.commit()
    return project_id


def _scan(scan_id, version, *, project_id="p1", commit="c1", creator=None, status="success"):
    _project(project_id)
    with db_module.SessionLocal() as db:
        db.add(Scan(
            id=scan_id, project_id=project_id, git_url="https://example.com/r.git", branch="main",
            commit_sha=commit, status=status, version=version, created_by_user_id=creator,
            metadata_json={"use_llm": True, "versions": {"engine_commit": f"engine-{version}"}},
        ))
        db.commit()
    return scan_id


def _finding(line, *, verdict="true_positive", rule="log-injection", cwe="CWE-117", expression="log.info(x)",
             path=ORDERS, **extra):
    finding = {
        "kind": "regex", "rule_id": rule, "cwe": cwe, "matched_text": expression, "file_path": path,
        "line": line, "severity": "HIGH", "title": "Log injection", "verdict": verdict,
        "confidence": 0.9 if verdict != "unverified" else None, "issue_class": "security",
        "verdict_reason": f"decided {verdict}",
    }
    if verdict == "unverified":
        finding["unresolved_reason"] = "not_reviewed_regex"
    finding.update(extra)
    return finding


def _write(occurrence, scan_id, findings, path=ORDERS):
    occurrence.stamp_identity(_FIXTURES, path, findings)
    _make_findings_writer(scan_id)(path, findings)


def _diff(client, scan_id, base, headers=ADMIN_HEADERS, **params):
    return client.get(f"/scans/{scan_id}/decision-diff", headers=headers, params={"base": base, **params})


@pytest.fixture()
def two_scans(occurrence, client):
    """A: two confirmed calls in first(), one unverified in second(), a yaml finding.
    B: the first call is now a false positive, the second call is gone, a new finding appears."""
    _scan("a", 1)
    _scan("b", 2)
    yaml = _finding(2, rule="secret", cwe="CWE-798", expression="password: hunter2", path="config.yaml",
                    verdict="unverified")
    _write(occurrence, "a", [_finding(7), _finding(8), _finding(12, verdict="unverified")])
    _write(occurrence, "a", [dict(yaml)], path="config.yaml")
    _write(occurrence, "b", [
        _finding(7, verdict="false_positive"), _finding(12, verdict="unverified"),
        _finding(12, rule="other-rule", cwe="CWE-20", expression="log.info(x)", verdict="true_positive"),
    ])
    _write(occurrence, "b", [dict(yaml)], path="config.yaml")
    return "a", "b"


# --- the diff -----------------------------------------------------------------

def test_one_flip_one_removal_and_one_addition_are_found_with_tp_to_fp_first(client, two_scans):
    base, scan = two_scans
    body = _diff(client, scan, base).json()
    assert body["counts"] == {
        "added": 1, "removed": 1, "verdict_changed": 1, "issue_class_changed": 0, "unchanged": 2,
    }
    by_change = {e["change"]: e for e in body["entries"]}
    assert set(by_change) == {"added", "removed", "verdict_changed"}  # unchanged omitted
    flipped = by_change["verdict_changed"]
    assert (flipped["old"]["verdict"], flipped["new"]["verdict"]) == ("true_positive", "false_positive")
    assert flipped["stage"] == "triage_regex" and flipped["verdict_reason"] == "decided false_positive"
    assert by_change["removed"]["new"] is None and by_change["removed"]["old"]["verdict"] == "true_positive"
    assert by_change["added"]["old"] is None and by_change["added"]["rule_id"] == "other-rule"
    assert body["summary"]["transitions"][0] == {"from": "true_positive", "to": "false_positive", "count": 1}
    assert body["summary"]["transitions"][1] == {"from": "true_positive", "to": "removed", "count": 1}
    assert {"from": "added", "to": "true_positive", "count": 1} in body["summary"]["transitions"]
    assert body["summary"]["by_rule"]["log-injection"] == {
        "added": 0, "removed": 1, "verdict_changed": 1, "issue_class_changed": 0,
    }


def test_the_evidence_versions_of_both_scans_are_reported(client, two_scans):
    base, scan = two_scans
    body = _diff(client, scan, base).json()
    assert body["scan"]["evidence_version"] == {"engine_commit": "engine-2"}
    assert body["base"]["evidence_version"] == {"engine_commit": "engine-1"}
    assert (body["scan"]["version"], body["base"]["version"]) == (2, 1)
    assert body["commit_differs"] is False


def test_identical_scans_give_an_empty_diff(occurrence, client):
    _scan("a", 1)
    _scan("b", 2)
    for scan_id in ("a", "b"):
        _write(occurrence, scan_id, [_finding(7), _finding(8), _finding(12, verdict="unverified")])
    body = _diff(client, "b", "a").json()
    assert body["entries"] == []
    assert body["counts"] == {"added": 0, "removed": 0, "verdict_changed": 0, "issue_class_changed": 0, "unchanged": 3}
    assert body["summary"]["transitions"] == []


def test_unchanged_entries_come_back_when_asked_for(client, two_scans):
    base, scan = two_scans
    body = _diff(client, scan, base, include_unchanged="true").json()
    assert len(body["entries"]) == 5
    assert [e["change"] for e in body["entries"]].count("unchanged") == 2


def test_an_issue_class_change_is_its_own_change(occurrence, client):
    _scan("a", 1)
    _scan("b", 2)
    _write(occurrence, "a", [_finding(7)])
    _write(occurrence, "b", [_finding(7, issue_class="quality")])
    body = _diff(client, "b", "a").json()
    (entry,) = body["entries"]
    assert entry["change"] == "issue_class_changed"
    assert (entry["old"]["issue_class"], entry["new"]["issue_class"]) == ("security", "quality")
    assert body["summary"]["transitions"] == []  # the verdict did not move


def test_a_line_shift_is_not_a_change(occurrence, client, tmp_path):
    """The same sink three lines further down, in a shifted copy of the file."""
    _scan("a", 1)
    _scan("b", 2)
    _write(occurrence, "a", [_finding(7)])
    shifted = [_finding(13, path="Orders_shifted.java")]
    occurrence.stamp_identity(_FIXTURES, "Orders_shifted.java", shifted)
    shifted[0]["file_path"] = ORDERS  # same logical file: the path is part of the identity
    _make_findings_writer("b")(ORDERS, shifted)
    body = _diff(client, "b", "a", include_unchanged="true").json()
    assert body["counts"]["unchanged"] == 1 and body["counts"]["added"] == body["counts"]["removed"] == 0


def test_a_file_level_join_is_marked(client, two_scans):
    base, scan = two_scans
    body = _diff(client, scan, base, include_unchanged="true").json()
    yaml = next(e for e in body["entries"] if e["file_path"] == "config.yaml")
    assert yaml["identity_quality"] == "file_level"
    assert body["file_level_joins"] == 1


def test_a_different_commit_is_flagged_but_allowed(occurrence, client):
    _scan("a", 1, commit="aaa")
    _scan("b", 2, commit="bbb")
    _write(occurrence, "a", [_finding(7)])
    _write(occurrence, "b", [_finding(7)])
    assert _diff(client, "b", "a").json()["commit_differs"] is True


def test_the_decision_stage_is_the_latest_one(occurrence, client):
    _scan("a", 1)
    _scan("b", 2)
    _write(occurrence, "a", [_finding(12, verdict="unverified")])
    _write(occurrence, "b", [_finding(12, verdict="unverified")])
    _make_verdict_updates_writer("b")(ORDERS, [{
        "rule_id": "log-injection", "line": 12, "verdict": "true_positive", "confidence": 0.9,
        "verdict_reason": "confirmed by the group review",
    }])
    (entry,) = _diff(client, "b", "a").json()["entries"]
    assert entry["change"] == "verdict_changed"
    assert entry["stage"] == "group_confirm" and entry["verdict_reason"] == "confirmed by the group review"


# --- who can compare what ------------------------------------------------------

def test_a_base_scan_from_another_project_is_422(occurrence, client):
    _scan("a", 1, project_id="p1")
    _scan("b", 1, project_id="p2")
    _write(occurrence, "a", [_finding(7)])
    _write(occurrence, "b", [_finding(7)])
    resp = _diff(client, "b", "a")
    assert resp.status_code == 422 and "same project" in resp.json()["detail"]


def test_a_base_scan_without_occurrence_ids_is_422_with_a_clear_message(occurrence, client):
    _scan("a", 1)
    _scan("b", 2)
    _write(occurrence, "b", [_finding(7)])
    with db_module.SessionLocal() as db:  # a pre-identity scan: findings, but no occurrence ids
        db.add(Finding(scan_id="a", severity="HIGH", title="old", verdict="true_positive", kind="llm",
                       rule_id="x", file_path="A.java", line=1))
        db.commit()
    resp = _diff(client, "b", "a")
    assert resp.status_code == 422
    assert "predates occurrence identity" in resp.json()["detail"] and "v1" in resp.json()["detail"]


def test_a_scan_with_no_findings_at_all_diffs_as_all_added(occurrence, client):
    _scan("a", 1)
    _scan("b", 2)
    _write(occurrence, "b", [_finding(7)])
    body = _diff(client, "b", "a").json()
    assert body["counts"]["added"] == 1


def test_a_base_scan_the_caller_cannot_see_is_404(occurrence, client):
    ada_id, _ada = make_user("ada@test.local")
    bob_id, bob = make_user("bob@test.local")
    _scan("a", 1, creator=ada_id)
    _scan("b", 2, creator=bob_id)
    _write(occurrence, "a", [_finding(7)])
    _write(occurrence, "b", [_finding(7)])
    assert _diff(client, "b", "a", headers=bob).status_code == 404
    assert _diff(client, "b", "does-not-exist", headers=bob).status_code == 404
    assert _diff(client, "b", "a").status_code == 200  # an admin sees both


def test_a_scan_the_caller_cannot_see_is_404_and_anonymous_is_401(occurrence, client):
    ada_id, ada = make_user("ada@test.local")
    _bob_id, bob = make_user("bob@test.local")
    _scan("a", 1, creator=ada_id)
    _scan("b", 2, creator=ada_id)
    assert _diff(client, "b", "a", headers=bob).status_code == 404
    assert _diff(client, "b", "a", headers=ada).status_code == 200
    assert client.get("/scans/b/decision-diff", params={"base": "a"}).status_code == 401
    assert client.get("/scans/b/decision-diff.xlsx", params={"base": "a"}).status_code == 401


def test_the_base_parameter_is_required(client, two_scans):
    assert client.get("/scans/b/decision-diff", headers=ADMIN_HEADERS).status_code == 422


# --- the Excel export ------------------------------------------------------------

def test_the_xlsx_has_one_row_per_json_entry(client, two_scans):
    base, scan = two_scans
    for params in ({}, {"include_unchanged": "true"}):
        entries = _diff(client, scan, base, **params).json()["entries"]
        resp = client.get(f"/scans/{scan}/decision-diff.xlsx", headers=ADMIN_HEADERS,
                          params={"base": base, **params})
        assert resp.status_code == 200
        assert "spreadsheetml" in resp.headers["content-type"]
        sheet = load_workbook(BytesIO(resp.content))["Changes"]
        assert sheet.max_row - 1 == len(entries)


def test_the_xlsx_summary_and_rows_match_the_json(client, two_scans):
    base, scan = two_scans
    body = _diff(client, scan, base).json()
    wb = load_workbook(BytesIO(client.get(
        f"/scans/{scan}/decision-diff.xlsx", headers=ADMIN_HEADERS, params={"base": base}).content))
    summary = {r[0]: r[1] for r in wb["Summary"].iter_rows(values_only=True) if r and r[0]}
    assert summary["Count — verdict_changed"] == 1 and summary["Count — removed"] == 1
    assert summary["true_positive → false_positive"] == 1
    changes = wb["Changes"]
    headers = [c.value for c in changes[1]]
    rows = [dict(zip(headers, r)) for r in changes.iter_rows(min_row=2, values_only=True)]
    assert {r["Occurrence ID"] for r in rows} == {e["occurrence_id"] for e in body["entries"]}
    assert {r["Change"] for r in rows} == {"added", "removed", "verdict_changed"}


def test_the_xlsx_is_refused_for_a_scan_the_caller_cannot_see(occurrence, client):
    ada_id, _ada = make_user("ada@test.local")
    _bob_id, bob = make_user("bob@test.local")
    _scan("a", 1, creator=ada_id)
    _scan("b", 2, creator=ada_id)
    resp = client.get("/scans/b/decision-diff.xlsx", headers=bob, params={"base": "a"})
    assert resp.status_code == 404


# --- the pure diff (the gate reuses it) ------------------------------------------

def _record(occurrence_id, verdict, **extra):
    return {"occurrence_id": occurrence_id, "verdict": verdict, "issue_class": "security",
            "rule_id": "r", "file_path": "A.java", "line": 1, **extra}


def test_diff_is_pure_over_records():
    result = dd.diff(
        [_record("1", "true_positive"), _record("2", "true_positive"), _record("3", "unverified")],
        [_record("1", "false_positive"), _record("3", "unverified"), _record("4", "true_positive")],
    )
    assert result["counts"] == {"added": 1, "removed": 1, "verdict_changed": 1, "issue_class_changed": 0, "unchanged": 1}
    assert [t["from"] + ">" + t["to"] for t in result["summary"]["transitions"]][:2] == [
        "true_positive>false_positive", "true_positive>removed",
    ]


def test_duplicate_occurrence_ids_collapse_to_the_strongest_row():
    result = dd.diff(
        [_record("1", "false_positive"), _record("1", "true_positive", confidence=0.4)],
        [_record("1", "false_positive")],
        include_unchanged=True,
    )
    (entry,) = result["entries"]
    assert entry["change"] == "verdict_changed" and entry["members"] == {"old": 2, "new": 1}
