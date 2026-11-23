"""Monitor -> LLM observability: GET /monitor/llm.

The numbers come from scans' own usage summaries."""

from datetime import datetime, timedelta, timezone

import pytest

from app.models import Project, Scan
from tests.test_auth_api import _db, _invite_and_accept, _setup_admin, client  # noqa: F401 — fixture


def _seed():
    now = datetime.now(timezone.utc)
    with _db() as db:
        project = Project(name="demo", default_git_url="https://example.com/demo.git")
        db.add(project)
        db.flush()
        db.add_all([
            Scan(project_id=project.id, git_url=project.default_git_url, status="success", scan_type="sast",
                 version=1, llm_provider="ollama", llm_model="qwen3:8b", created_at=now - timedelta(hours=2),
                 metadata_json={"usage_summary": {
                     "provider": "ollama", "model": "qwen3:8b", "input_tokens": 1000, "output_tokens": 200,
                     "cost_usd": 0.0, "call_count": 4, "result_cache_hits": 1,
                     "by_step": {"scan_deep_files": {"calls": 3, "input_tokens": 900, "output_tokens": 150},
                                 "group_confirm_triage_findings": {"calls": 1, "input_tokens": 100, "output_tokens": 50}},
                 }}),
            Scan(project_id=project.id, git_url=project.default_git_url, status="success", scan_type="sast",
                 version=2, llm_provider="bedrock", llm_model="haiku", created_at=now - timedelta(days=1),
                 metadata_json={"usage_summary": {
                     "provider": "bedrock", "model": "haiku", "input_tokens": 3000, "output_tokens": 600,
                     "cost_usd": 0.75, "call_count": 6, "fallback_switched": True,
                     "by_step": {"scan_deep_files": {"calls": 6, "input_tokens": 3000, "output_tokens": 600}},
                 }}),
            Scan(project_id=project.id, git_url=project.default_git_url, status="failed", scan_type="sast",
                 version=3, created_at=now - timedelta(hours=1), metadata_json={}),
            # outside the 7-day range
            Scan(project_id=project.id, git_url=project.default_git_url, status="success", scan_type="sast",
                 version=4, created_at=now - timedelta(days=20),
                 metadata_json={"usage_summary": {"call_count": 99, "cost_usd": 9.0}}),
        ])
        db.commit()
        return project.id


def test_admin_sees_db_metrics(client):  # noqa: F811
    admin = _setup_admin(client)
    _seed()
    r = client.get("/monitor/llm?range=7d", headers=admin)
    assert r.status_code == 200, r.text
    body = r.json()
    t = body["totals"]
    assert (t["scans"], t["scans_with_llm"], t["scans_without_usage"], t["failed_scans"]) == (3, 2, 1, 1)
    assert (t["llm_calls"], t["input_tokens"], t["output_tokens"]) == (10, 4000, 800)
    assert t["cost_usd"] == pytest.approx(0.75)
    assert t["result_cache_hits"] == 1 and t["result_cache_hit_rate"] == pytest.approx(1 / 11, abs=1e-4)
    assert t["fallback_scans"] == 1
    assert body["granularity"] == "day" and len(body["series"]) in (7, 8)
    assert sum(p["calls"] for p in body["series"]) == 10
    assert [m["model"] for m in body["by_model"]] == ["haiku", "qwen3:8b"]
    deep = next(s for s in body["by_step"] if s["step"] == "scan_deep_files")
    assert deep["calls"] == 9 and deep["input_tokens"] == 3900
    assert [s["version"] for s in body["top_scans"]] == [2, 1]
    assert "langfuse" not in body


def test_monitor_is_admin_only(client):  # noqa: F811
    admin = _setup_admin(client)
    _, user = _invite_and_accept(client, admin)
    assert client.get("/monitor/llm", headers=user).status_code == 403
    assert client.get("/monitor/llm").status_code == 401
    me = client.get("/auth/me", headers=user).json()
    assert "page.monitor" not in me["pages"]
    assert "page.monitor" in client.get("/auth/me", headers=admin).json()["pages"]


def test_unknown_range_is_rejected(client):  # noqa: F811
    admin = _setup_admin(client)
    assert client.get("/monitor/llm?range=1y", headers=admin).status_code == 422
