from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.db import init_db
from app.main import app

from tests.auth_helpers import ADMIN_HEADERS  # noqa: E402

HDR = ADMIN_HEADERS


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    settings.use_mock_engine = True
    settings.scan_logs_dir = str(tmp_path / "scan_logs")
    url = f"sqlite:///{(tmp_path / 'test.db').as_posix()}"
    init_db(url)
    # Do NOT use `with TestClient(app)` here: entering the context triggers
    # the app's startup event, which calls init_db() with no args and would
    # reset the engine back to the production database_url, undoing the
    # tmp_path db we just set up above.
    return TestClient(app)


@pytest.fixture()
def project_id(client):
    payload = {
        "name": "scan-target",
        "default_git_url": "https://github.com/org/repo.git",
    }
    resp = client.post("/projects", json=payload, headers=HDR)
    assert resp.status_code == 201
    return resp.json()["id"]


def test_trigger_scan_idempotent(client, project_id):
    payload = {"project_id": project_id, "commit_sha": "abc123", "branch": "main"}
    r1 = client.post("/scans", headers=HDR, json=payload)
    r2 = client.post("/scans", headers=HDR, json=payload)
    assert r1.status_code == 202
    assert r2.status_code == 202
    assert r2.json()["scan_id"] == r1.json()["scan_id"]


def test_scan_list_includes_local_root_path(client, project_id):
    payload = {"project_id": project_id, "commit_sha": "abc123", "branch": "main"}
    client.post("/scans", headers=HDR, json=payload)

    resp = client.get("/scans", headers=HDR, params={"project_id": project_id})
    assert resp.status_code == 200
    scans = resp.json()
    assert len(scans) == 1
    expected_root = str(Path(settings.workspaces_dir) / project_id)
    assert scans[0]["local_root_path"] == expected_root
    assert scans[0]["repo_path"] is None


def test_scan_list_local_root_path_includes_repo_path_scope(client, project_id):
    payload = {
        "project_id": project_id,
        "commit_sha": "abc123",
        "branch": "main",
        "repo_path": "services/api",
    }
    client.post("/scans", headers=HDR, json=payload)

    resp = client.get("/scans", headers=HDR, params={"project_id": project_id})
    scans = resp.json()
    assert len(scans) == 1
    expected_root = str(Path(settings.workspaces_dir) / project_id / "services/api")
    assert scans[0]["local_root_path"] == expected_root
    assert scans[0]["repo_path"] == "services/api"


def test_force_creates_new_scan(client, project_id):
    payload = {"project_id": project_id, "commit_sha": "abc123", "force": True}
    r1 = client.post("/scans", headers=HDR, json=payload)
    r2 = client.post("/scans", headers=HDR, json=payload)
    assert r1.json()["scan_id"] != r2.json()["scan_id"]


def test_trigger_scan_without_commit_sha_reuses_scan_when_git_head_unchanged(
    client, project_id, monkeypatch
):
    from app.services import git_workspace

    monkeypatch.setattr(git_workspace, "resolve_remote_head", lambda git_url, branch, *args, **kwargs: "same-sha")

    payload = {"project_id": project_id}
    r1 = client.post("/scans", headers=HDR, json=payload)
    r2 = client.post("/scans", headers=HDR, json=payload)

    assert r1.status_code == 202
    assert r1.json()["reused"] is False
    assert r2.json()["reused"] is True
    assert r2.json()["scan_id"] == r1.json()["scan_id"]
    assert "No changes" in r2.json()["reused_reason"]


def test_trigger_scan_without_commit_sha_creates_new_scan_when_git_head_changes(
    client, project_id, monkeypatch
):
    from app.services import git_workspace

    heads = iter(["sha-one", "sha-two"])
    monkeypatch.setattr(git_workspace, "resolve_remote_head", lambda git_url, branch, *args, **kwargs: next(heads))

    payload = {"project_id": project_id}
    r1 = client.post("/scans", headers=HDR, json=payload)
    r2 = client.post("/scans", headers=HDR, json=payload)

    assert r2.json()["reused"] is False
    assert r1.json()["scan_id"] != r2.json()["scan_id"]


def test_trigger_scan_without_commit_sha_falls_back_when_git_unreachable(
    client, project_id, monkeypatch
):
    from app.services import git_workspace

    monkeypatch.setattr(git_workspace, "resolve_remote_head", lambda git_url, branch, *args, **kwargs: None)

    payload = {"project_id": project_id}
    r1 = client.post("/scans", headers=HDR, json=payload)
    r2 = client.post("/scans", headers=HDR, json=payload)

    assert r1.status_code == 202
    assert r2.json()["reused"] is False
    assert r1.json()["scan_id"] != r2.json()["scan_id"]


def test_trigger_scan_does_not_reuse_a_failed_scan_for_same_commit(client, project_id):
    payload = {"project_id": project_id, "commit_sha": "flaky-commit"}
    created = client.post("/scans", headers=HDR, json=payload).json()

    from app.db import SessionLocal
    from app.models import Scan

    db = SessionLocal()
    try:
        scan = db.get(Scan, created["scan_id"])
        scan.status = "failed"
        scan.message = "boom"
        db.commit()
    finally:
        db.close()

    retried = client.post("/scans", headers=HDR, json=payload).json()
    assert retried["scan_id"] != created["scan_id"]


def test_trigger_scan_without_auth_returns_401(client, project_id):
    payload = {"project_id": project_id, "commit_sha": "abc123"}
    resp = client.post("/scans", json=payload)
    assert resp.status_code == 401


def test_trigger_scan_unknown_project_returns_404(client):
    payload = {"project_id": "does-not-exist", "commit_sha": "abc123"}
    resp = client.post("/scans", headers=HDR, json=payload)
    assert resp.status_code == 404


def test_trigger_scan_resolves_git_url_from_project(client, project_id):
    payload = {"project_id": project_id, "commit_sha": "resolve-me"}
    resp = client.post("/scans", headers=HDR, json=payload)
    assert resp.status_code == 202
    scan_id = resp.json()["scan_id"]
    status_resp = client.get(f"/scans/{scan_id}/status", headers=HDR)
    assert status_resp.status_code == 200


def test_get_status_returns_valid_status_value(client, project_id):
    payload = {"project_id": project_id, "commit_sha": "status-check"}
    created = client.post("/scans", headers=HDR, json=payload).json()
    resp = client.get(f"/scans/{created['scan_id']}/status", headers=HDR)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] in ("queued", "running", "success", "failed")
    assert body["scan_id"] == created["scan_id"]


def test_list_scans_includes_llm_snapshot_from_project(client, project_id):
    client.patch(
        f"/projects/{project_id}",
        json={"llm_provider": "ollama", "llm_model": "granite-code:3b"},
        headers=HDR,
    )
    created = client.post(
        "/scans",
        headers=HDR,
        json={"project_id": project_id, "commit_sha": "llm-snap", "force": True},
    ).json()
    listed = client.get("/scans", headers=HDR).json()
    row = next(s for s in listed if s["id"] == created["scan_id"])
    assert row["llm_provider"] == "ollama"
    assert row["llm_model"] == "granite-code:3b"


def test_trigger_from_app_sets_triggered_by_app(client, project_id):
    created = client.post(
        "/scans",
        headers=HDR,
        json={
            "project_id": project_id,
            "commit_sha": "from-app",
            "force": True,
            "metadata": {"source": "app"},
        },
    ).json()
    listed = client.get("/scans", headers=HDR).json()
    row = next(s for s in listed if s["id"] == created["scan_id"])
    assert row["triggered_by"] == "app"


def test_trigger_from_jenkins_sets_triggered_by_jenkins(client, project_id):
    created = client.post(
        "/scans",
        headers=HDR,
        json={
            "project_id": project_id,
            "commit_sha": "from-jenkins",
            "force": True,
            "metadata": {"source": "jenkins", "jenkins_build": "http://jenkins/job/1"},
        },
    ).json()
    listed = client.get("/scans", headers=HDR).json()
    row = next(s for s in listed if s["id"] == created["scan_id"])
    assert row["triggered_by"] == "jenkins"


def test_trigger_scan_accepts_llm_override(client, project_id):
    created = client.post(
        "/scans",
        headers=HDR,
        json={
            "project_id": project_id,
            "commit_sha": "sources-llm",
            "force": True,
            "llm_provider": "ollama",
            "llm_model": "granite-code:8b",
        },
    ).json()
    assert created["scan_id"]
    from app.db import SessionLocal
    from app.models import Scan

    db = SessionLocal()
    try:
        scan = db.get(Scan, created["scan_id"])
        assert scan is not None
        assert scan.llm_provider == "ollama"
        assert scan.llm_model == "granite-code:8b"
        assert scan.metadata_json.get("use_llm") is True
    finally:
        db.close()


def test_trigger_scan_use_llm_false_clears_llm_snapshot(client, project_id):
    created = client.post(
        "/scans",
        headers=HDR,
        json={
            "project_id": project_id,
            "commit_sha": "no-llm",
            "force": True,
            "use_llm": False,
            "llm_provider": "ollama",
            "llm_model": "granite-code:8b",
        },
    ).json()
    assert created["scan_id"]
    from app.db import SessionLocal
    from app.models import Scan

    db = SessionLocal()
    try:
        scan = db.get(Scan, created["scan_id"])
        assert scan is not None
        assert scan.metadata_json.get("use_llm") is False
        assert scan.llm_provider is None
        assert scan.llm_model is None
    finally:
        db.close()


def test_get_status_unknown_scan_returns_404(client):
    resp = client.get("/scans/does-not-exist/status", headers=HDR)
    assert resp.status_code == 404


def test_get_logs_returns_engine_output_for_completed_scan(client, project_id):
    payload = {"project_id": project_id, "commit_sha": "logs-check"}
    created = client.post("/scans", headers=HDR, json=payload).json()
    assert created["status"] == "success"

    resp = client.get(f"/scans/{created['scan_id']}/logs", headers=HDR)
    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_id"] == created["scan_id"]
    assert body["status"] == "success"
    assert body["next_after"] >= 1
    texts = [row["line"] for row in body["lines"]]
    assert any("Starting scan" in line for line in texts)
    assert any("Scan complete" in line for line in texts)
    assert any("STAGE" in line for line in texts)

    # Incremental poll: after=next_after should yield no new lines
    again = client.get(
        f"/scans/{created['scan_id']}/logs?after={body['next_after']}",
        headers=HDR,
    ).json()
    assert again["lines"] == []
    assert again["next_after"] == body["next_after"]


def test_get_status_without_auth_returns_401(client, project_id):
    payload = {"project_id": project_id, "commit_sha": "auth-check"}
    created = client.post("/scans", headers=HDR, json=payload).json()
    resp = client.get(f"/scans/{created['scan_id']}/status")
    assert resp.status_code == 401


def test_get_results_after_completion_returns_discovery(client, project_id):
    payload = {"project_id": project_id, "commit_sha": "results-check"}
    created = client.post("/scans", headers=HDR, json=payload).json()
    assert created["status"] == "success"

    resp = client.get(f"/scans/{created['scan_id']}/results", headers=HDR)
    assert resp.status_code == 200
    body = resp.json()
    assert "discovery" in body
    discovery = body["discovery"]
    assert discovery["llm_analysis"]["tech_stack"]
    assert discovery["scan_summary"]["total_files"] > 0
    assert discovery["module_plan"]["risk_counts"]["CRITICAL"] >= 1


def test_get_results_unknown_scan_returns_404(client):
    resp = client.get("/scans/does-not-exist/results", headers=HDR)
    assert resp.status_code == 404


def test_get_scan_logs_returns_lifecycle_lines_and_supports_incremental_after(
    client, project_id
):
    payload = {"project_id": project_id, "commit_sha": "logs-check"}
    created = client.post("/scans", headers=HDR, json=payload).json()
    scan_id = created["scan_id"]

    resp = client.get(f"/scans/{scan_id}/logs", headers=HDR)
    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_id"] == scan_id
    assert body["status"] == "success"
    assert len(body["lines"]) >= 2
    assert any("Starting scan" in item["line"] for item in body["lines"])
    assert any("Scan complete" in item["line"] for item in body["lines"])
    assert all(item["seq"] > 0 for item in body["lines"])

    # Re-polling with `next_after` from the first response returns no more lines.
    follow_up = client.get(
        f"/scans/{scan_id}/logs", headers=HDR, params={"after": body["next_after"]}
    ).json()
    assert follow_up["lines"] == []
    assert follow_up["next_after"] == body["next_after"]


def test_get_scan_logs_unknown_scan_returns_404(client):
    resp = client.get("/scans/does-not-exist/logs", headers=HDR)
    assert resp.status_code == 404


def test_get_scan_logs_without_auth_returns_401(client, project_id):
    payload = {"project_id": project_id, "commit_sha": "logs-auth-check"}
    created = client.post("/scans", headers=HDR, json=payload).json()
    resp = client.get(f"/scans/{created['scan_id']}/logs")
    assert resp.status_code == 401


def test_trigger_refuses_when_fallback_model_missing(client, project_id, monkeypatch):

    monkeypatch.setattr(settings, "use_mock_engine", False)
    monkeypatch.setattr(settings, "run_live_sast", True)
    import io, json
    from app.services import ollama_check
    body = json.dumps({"models": [{"name": "phi4-mini:3.8b"}]}).encode()
    monkeypatch.setattr(ollama_check.urllib.request, "urlopen", lambda *a, **k: io.BytesIO(body))
    resp = client.post(
        "/scans",
        headers=HDR,
        json={"project_id": project_id, "commit_sha": "ol-1", "force": True},
    )
    assert resp.status_code == 400
    assert "granite-code:3b-instruct" in resp.json()["detail"]
