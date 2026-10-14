"""Learned agentic-hunt rules: promoted on one scan, run on the next."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.db import init_db
from app.main import app
from app.services import learned_rules
from app.services.learned_rules import MAX_LEARNED_RULES_PER_PROJECT, learned_rule_id, merge_promoted_rules

HDR = {"Authorization": f"Bearer {settings.sast_api_token}"}


def _discovery(*rows):
    return {"report": {"hunt": {"learned_rules": list(rows)}}}


def _promoted(pattern, cwe="CWE-89"):
    return {"status": "promoted", "pattern": pattern, "positives": ["Dao.java:15"],
            "rule": {"id": "learned-cwe-89-1", "title": "Learned: SQLi", "cwe": cwe, "severity": "MEDIUM",
                     "pattern": pattern, "languages": ["java"], "derived": True}}


def test_merge_adds_promoted_rules_with_stable_ids_and_provenance():
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    merged = merge_promoted_rules(None, _discovery(
        _promoted(r"executeQuery\(\"SELECT .*\+"),
        {"status": "rejected", "pattern": "noise", "reasons": ["too noisy"]},
    ), scan_id="s1", now=t0)
    assert [r["pattern"] for r in merged] == [r"executeQuery\(\"SELECT .*\+"]
    rule = merged[0]
    # Stable id from the pattern, not the per-scan counter.
    assert rule["id"] == learned_rule_id("CWE-89", r"executeQuery\(\"SELECT .*\+")
    assert rule["learned_from_scan_id"] == "s1" and rule["derived"] is True

    # Promoted again later: refreshed, not duplicated.
    again = merge_promoted_rules(merged, _discovery(_promoted(r"executeQuery\(\"SELECT .*\+")),
                                 scan_id="s2", now=t0 + timedelta(days=1))
    assert len(again) == 1
    assert again[0]["learned_from_scan_id"] == "s1" and again[0]["last_confirmed_scan_id"] == "s2"


def test_merge_skips_invalid_patterns_reports_no_change_and_caps():
    assert merge_promoted_rules([], _discovery(_promoted("(unclosed")), scan_id="s") is None
    assert merge_promoted_rules([], {"report": {}}, scan_id="s") is None
    rows = [_promoted(f"pattern{i}x") for i in range(MAX_LEARNED_RULES_PER_PROJECT + 5)]
    merged = merge_promoted_rules([], _discovery(*rows), scan_id="s")
    assert len(merged) == MAX_LEARNED_RULES_PER_PROJECT


def test_scan_runner_remembers_promotions_on_the_project(monkeypatch):
    from app.services import scan_runner

    monkeypatch.setattr(scan_runner.scan_log, "log", lambda *_a, **_k: None)
    project = SimpleNamespace(learned_rules=None)
    scan = SimpleNamespace(id="scan-1", project=project)
    scan_runner._remember_learned_rules(scan, _discovery(_promoted(r"Runtime\.getRuntime\(\)\.exec\(cmd")))
    assert project.learned_rules[0]["pattern"] == r"Runtime\.getRuntime\(\)\.exec\(cmd"
    before = list(project.learned_rules)
    scan_runner._remember_learned_rules(scan, {"report": {}})
    assert project.learned_rules == before


@pytest.fixture()
def client(tmp_path):
    init_db(f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    return TestClient(app)


def test_project_exposes_and_deletes_learned_rules(client):
    from app.db import SessionLocal
    from app.models import Project

    pid = client.post("/projects", json={"name": "learned", "default_git_url": "https://e.x/r.git"},
                      headers=HDR).json()["id"]
    assert client.get(f"/projects/{pid}", headers=HDR).json()["learned_rules"] == []
    with SessionLocal() as db:
        project = db.get(Project, pid)
        project.learned_rules = merge_promoted_rules(None, _discovery(_promoted(r"a\.b\(c")), scan_id="s")
        db.commit()
    rules = client.get(f"/projects/{pid}", headers=HDR).json()["learned_rules"]
    assert len(rules) == 1
    assert client.delete(f"/projects/{pid}/learned-rules/nope", headers=HDR).status_code == 404
    resp = client.delete(f"/projects/{pid}/learned-rules/{rules[0]['id']}", headers=HDR)
    assert resp.status_code == 200 and resp.json()["learned_rules"] == []
