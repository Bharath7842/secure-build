from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.db import init_db
from app.main import app

HDR = {"Authorization": f"Bearer {settings.sast_api_token}"}


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


@pytest.mark.parametrize("filename", ["0.jpg", "login.jpg"])
def test_get_dast_screenshot_returns_the_file(client, project_id, filename):
    payload = {"project_id": project_id, "commit_sha": "shot-check"}
    scan_id = client.post("/scans", headers=HDR, json=payload).json()["scan_id"]
    shot_dir = Path(settings.dast_screenshots_dir) / scan_id
    shot_dir.mkdir(parents=True, exist_ok=True)
    (shot_dir / filename).write_bytes(b"\xff\xd8\xff\xe0fake-jpeg-bytes")

    resp = client.get(f"/scans/{scan_id}/screenshots/{filename}", headers=HDR)
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/jpeg"
    assert resp.content == b"\xff\xd8\xff\xe0fake-jpeg-bytes"


def test_get_dast_screenshot_unknown_scan_returns_404(client):
    resp = client.get("/scans/does-not-exist/screenshots/0.jpg", headers=HDR)
    assert resp.status_code == 404


def test_get_dast_screenshot_missing_file_returns_404(client, project_id):
    payload = {"project_id": project_id, "commit_sha": "shot-missing"}
    scan_id = client.post("/scans", headers=HDR, json=payload).json()["scan_id"]
    resp = client.get(f"/scans/{scan_id}/screenshots/0.jpg", headers=HDR)
    assert resp.status_code == 404


@pytest.mark.parametrize("filename", ["../../etc/passwd", "..%2F..%2Fetc%2Fpasswd", "0.png", "0.jpg.exe", "../0.jpg", "0.jpg/../../x"])
def test_get_dast_screenshot_rejects_non_matching_filenames(client, project_id, filename):
    payload = {"project_id": project_id, "commit_sha": "shot-traversal"}
    scan_id = client.post("/scans", headers=HDR, json=payload).json()["scan_id"]
    resp = client.get(f"/scans/{scan_id}/screenshots/{filename}", headers=HDR)
    assert resp.status_code == 404


def test_get_dast_screenshot_without_auth_returns_401(client, project_id):
    payload = {"project_id": project_id, "commit_sha": "shot-auth-check"}
    scan_id = client.post("/scans", headers=HDR, json=payload).json()["scan_id"]
    resp = client.get(f"/scans/{scan_id}/screenshots/0.jpg")
    assert resp.status_code == 401


def test_delete_scan_removes_scan(client, project_id):
    payload = {"project_id": project_id, "commit_sha": "delete-me"}
    created = client.post("/scans", headers=HDR, json=payload).json()
    scan_id = created["scan_id"]
    assert created["status"] == "success"

    results = client.get(f"/scans/{scan_id}/results", headers=HDR)
    assert results.status_code == 200
    assert results.json()["discovery"] is not None

    deleted = client.delete(f"/scans/{scan_id}", headers=HDR)
    assert deleted.status_code == 204

    assert client.get(f"/scans/{scan_id}/status", headers=HDR).status_code == 404
    assert client.get(f"/scans/{scan_id}/results", headers=HDR).status_code == 404


def test_delete_scan_unknown_returns_404(client):
    resp = client.delete("/scans/does-not-exist", headers=HDR)
    assert resp.status_code == 404


def test_delete_scan_while_running_returns_409(client, project_id, monkeypatch):
    from app.services import scan_runner

    monkeypatch.setattr(scan_runner, "execute_scan", lambda scan_id: None)

    created = client.post(
        "/scans", headers=HDR, json={"project_id": project_id, "commit_sha": "still-alive"}
    ).json()
    assert created["status"] == "queued"

    resp = client.delete(f"/scans/{created['scan_id']}", headers=HDR)
    assert resp.status_code == 409
    assert "Stop" in resp.json()["detail"]


def test_cancel_running_scan(client, project_id, monkeypatch):
    from app.services import scan_runner

    monkeypatch.setattr(scan_runner, "execute_scan", lambda scan_id: None)

    created = client.post(
        "/scans", headers=HDR, json={"project_id": project_id, "commit_sha": "cancel-me"}
    ).json()
    scan_id = created["scan_id"]

    resp = client.post(f"/scans/{scan_id}/cancel", headers=HDR)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "cancelled"
    assert body["progress"] == 100

    deleted = client.delete(f"/scans/{scan_id}", headers=HDR)
    assert deleted.status_code == 204


def test_cancel_scan_spawns_reconcile_thread(client, project_id, monkeypatch):
    """`POST /scans/{id}/cancel` must fire-and-forget a background sweep for
    any findings left `unverified` by the abort, capped since a mid-run
    cancellation can leave a much larger backlog than usual."""
    from app.routers import scans as scans_router
    from app.services import scan_runner

    monkeypatch.setattr(scan_runner, "execute_scan", lambda scan_id: None)

    spawned = []

    class _FakeThread:
        def __init__(self, *args, **kwargs):
            spawned.append((args, kwargs))

        def start(self):
            pass  # never actually run the sweep in this test

    monkeypatch.setattr(scans_router.threading, "Thread", _FakeThread)

    created = client.post(
        "/scans", headers=HDR, json={"project_id": project_id, "commit_sha": "cancel-reconcile"}
    ).json()
    scan_id = created["scan_id"]

    resp = client.post(f"/scans/{scan_id}/cancel", headers=HDR)
    assert resp.status_code == 200

    assert len(spawned) == 1
    _args, kwargs = spawned[0]
    assert kwargs["target"] is scan_runner.reconcile_unverified_findings
    assert kwargs["args"] == (scan_id,)
    assert kwargs["kwargs"] == {"capped": True}
    assert kwargs["daemon"] is True


def test_cancelled_scan_exposes_partial_findings_in_results(client, project_id, monkeypatch):
    from app.db import SessionLocal
    from app.models import Finding
    from app.services import scan_runner

    monkeypatch.setattr(scan_runner, "execute_scan", lambda scan_id: None)

    created = client.post(
        "/scans", headers=HDR, json={"project_id": project_id, "commit_sha": "partial-findings"}
    ).json()
    scan_id = created["scan_id"]

    db = SessionLocal()
    try:
        db.add(
            Finding(
                scan_id=scan_id,
                severity="HIGH",
                title="SQL injection",
                file_path="src/App.java",
                line=10,
                verdict="true_positive",
                owasp_category="A03:2021-Injection",
                kind="llm",
            )
        )
        db.add(
            Finding(
                scan_id=scan_id,
                severity="MEDIUM",
                title="False alarm",
                file_path="src/App.java",
                line=20,
                verdict="false_positive",
                kind="llm",
            )
        )
        db.commit()
    finally:
        db.close()

    resp = client.post(f"/scans/{scan_id}/cancel", headers=HDR)
    assert resp.status_code == 200

    findings = client.get(f"/scans/{scan_id}/findings", headers=HDR).json()
    assert findings["tp_count"] == 1
    assert findings["fp_count"] == 1
    assert findings["files_scanned"] == 1

    results = client.get(f"/scans/{scan_id}/results", headers=HDR).json()
    report = results["discovery"]["report"]
    assert report["tp_count"] == 1
    assert report["fp_count"] == 1
    assert report["files_scanned"] == 1

    pdf = client.get(f"/scans/{scan_id}/export.pdf", headers=HDR)
    assert pdf.status_code == 200
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content[:4] == b"%PDF"

    xlsx = client.get(f"/scans/{scan_id}/export.xlsx", headers=HDR)
    assert xlsx.status_code == 200
    assert xlsx.content[:2] == b"PK"


def test_cancel_completed_scan_returns_409(client, project_id):
    created = client.post(
        "/scans", headers=HDR, json={"project_id": project_id, "commit_sha": "done-cancel"}
    ).json()
    resp = client.post(f"/scans/{created['scan_id']}/cancel", headers=HDR)
    assert resp.status_code == 409


def test_delete_scan_without_auth_returns_401(client, project_id):
    created = client.post(
        "/scans", headers=HDR, json={"project_id": project_id, "commit_sha": "auth-del"}
    ).json()
    resp = client.delete(f"/scans/{created['scan_id']}")
    assert resp.status_code == 401


def test_get_results_while_running_returns_409(client, project_id, monkeypatch):
    from app.services import scan_runner

    monkeypatch.setattr(scan_runner, "execute_scan", lambda scan_id: None)

    payload = {"project_id": project_id, "commit_sha": "still-running"}
    created = client.post("/scans", headers=HDR, json=payload).json()
    assert created["status"] == "queued"

    resp = client.get(f"/scans/{created['scan_id']}/results", headers=HDR)
    assert resp.status_code == 409


def test_get_results_while_running_returns_partial_discovery(client, project_id, monkeypatch):
    """Once Mapping module risk persists discovery, results are available mid-scan."""
    from app.db import SessionLocal
    from app.models import Scan
    from app.services import scan_runner

    monkeypatch.setattr(scan_runner, "execute_scan", lambda scan_id: None)

    payload = {"project_id": project_id, "commit_sha": "partial-discovery"}
    created = client.post("/scans", headers=HDR, json=payload).json()
    scan_id = created["scan_id"]

    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        assert scan is not None
        scan.status = "running"
        scan.metadata_json = {
            **(scan.metadata_json or {}),
            "discovery": {
                "scan_summary": {"total_files": 2},
                "llm_analysis": {"tech_stack": "Python", "project_type": "web", "confidence": "low",
                                 "heuristic_stacks": ["python"], "llm_used": False, "risk_areas": [],
                                 "reasoning": ""},
                "categorized_counts": {"source": 1, "config": 0, "dependency": 0, "test": 1, "build": 0, "other": 0},
                "module_plan": {"modules_by_stack": {}, "risk_counts": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 1},
                                "files": [], "scan_priority": []},
                "report": None,
            },
        }
        db.commit()
    finally:
        db.close()

    resp = client.get(f"/scans/{scan_id}/results", headers=HDR)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "running"
    assert body["discovery"]["llm_analysis"]["tech_stack"] == "Python"
    assert body["discovery"]["report"] is None


def test_list_scans_filters_by_project(client, project_id):
    client.post("/scans", headers=HDR, json={"project_id": project_id, "commit_sha": "list-1"})
    resp = client.get(f"/scans?project_id={project_id}", headers=HDR)
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) >= 1
    assert all(s["project_id"] == project_id for s in body)


def test_list_scans_without_auth_returns_401(client):
    resp = client.get("/scans")
    assert resp.status_code == 401


def test_scan_version_increments_per_project(client, project_id):
    r1 = client.post(
        "/scans", headers=HDR, json={"project_id": project_id, "commit_sha": "v-c1"}
    ).json()
    r2 = client.post(
        "/scans", headers=HDR, json={"project_id": project_id, "commit_sha": "v-c2"}
    ).json()

    scans = {s["id"]: s["version"] for s in client.get(f"/scans?project_id={project_id}", headers=HDR).json()}
    assert scans[r1["scan_id"]] == 1
    assert scans[r2["scan_id"]] == 2


def test_scan_version_is_independent_per_project(client):
    project_a = client.post(
        "/projects",
        headers=HDR,
        json={"name": "ver-project-a", "default_git_url": "https://github.com/org/a.git"},
    ).json()
    project_b = client.post(
        "/projects",
        headers=HDR,
        json={"name": "ver-project-b", "default_git_url": "https://github.com/org/b.git"},
    ).json()

    scan_a1 = client.post(
        "/scans", headers=HDR, json={"project_id": project_a["id"], "commit_sha": "a1"}
    ).json()
    scan_b1 = client.post(
        "/scans", headers=HDR, json={"project_id": project_b["id"], "commit_sha": "b1"}
    ).json()

    scans_a = {s["id"]: s["version"] for s in client.get(f"/scans?project_id={project_a['id']}", headers=HDR).json()}
    scans_b = {s["id"]: s["version"] for s in client.get(f"/scans?project_id={project_b['id']}", headers=HDR).json()}
    assert scans_a[scan_a1["scan_id"]] == 1
    assert scans_b[scan_b1["scan_id"]] == 1


def test_get_results_reports_risk_areas_from_discovery(client):
    payload = {
        "name": "discovery-project",
        "default_git_url": "https://github.com/org/strict.git",
    }
    project = client.post("/projects", json=payload, headers=HDR).json()

    created = client.post(
        "/scans", headers=HDR, json={"project_id": project["id"], "commit_sha": "gate-check"}
    ).json()
    assert created["status"] == "success"

    results = client.get(f"/scans/{created['scan_id']}/results", headers=HDR).json()
    discovery = results["discovery"]
    assert discovery["llm_analysis"]["risk_areas"]
    assert discovery["categorized_counts"]["source"] >= 1


# ===========================================================================
# scan_type=sca
# ===========================================================================


def test_trigger_sca_scan_round_trips_scan_type(client, project_id):
    payload = {"project_id": project_id, "commit_sha": "sca-1", "scan_type": "sca"}
    created = client.post("/scans", headers=HDR, json=payload).json()
    assert created["scan_id"]

    status_resp = client.get(f"/scans/{created['scan_id']}/status", headers=HDR)
    assert status_resp.status_code == 200
    assert status_resp.json()["scan_type"] == "sca"
    assert status_resp.json()["status"] == "success"

    listed = client.get(
        "/scans", headers=HDR, params={"project_id": project_id, "scan_type": "sca"}
    ).json()
    assert any(s["id"] == created["scan_id"] and s["scan_type"] == "sca" for s in listed)

    sast_listed = client.get(
        "/scans", headers=HDR, params={"project_id": project_id, "scan_type": "sast"}
    ).json()
    assert all(s["id"] != created["scan_id"] for s in sast_listed)


def test_sca_scan_produces_dependency_discovery_via_mock_engine(client, project_id):
    payload = {"project_id": project_id, "commit_sha": "sca-mock", "scan_type": "sca"}
    created = client.post("/scans", headers=HDR, json=payload).json()

    results = client.get(f"/scans/{created['scan_id']}/results", headers=HDR).json()
    discovery = results["discovery"]
    assert discovery is not None
    assert discovery["dependency_summary"]["total_dependencies"] > 0
    assert "dependencies" in discovery


def test_sca_scan_defaults_llm_fields_to_none(client, project_id):
    created = client.post(
        "/scans",
        headers=HDR,
        json={
            "project_id": project_id,
            "commit_sha": "sca-no-llm",
            "scan_type": "sca",
            "llm_provider": "ollama",
            "llm_model": "granite-code:8b",
        },
    ).json()
    from app.db import SessionLocal
    from app.models import Scan

    db = SessionLocal()
    try:
        scan = db.get(Scan, created["scan_id"])
        assert scan is not None
        assert scan.llm_provider is None
        assert scan.llm_model is None
    finally:
        db.close()


def test_trigger_sca_scan_rejected_when_project_disables_sca(client, project_id):
    resp = client.patch(f"/projects/{project_id}", json={"enable_sca": False}, headers=HDR)
    assert resp.status_code == 200

    payload = {"project_id": project_id, "commit_sha": "sca-disabled", "scan_type": "sca"}
    resp = client.post("/scans", headers=HDR, json=payload)
    assert resp.status_code == 400


def test_trigger_scan_invalid_scan_type_returns_400(client, project_id):
    payload = {"project_id": project_id, "commit_sha": "bad-type", "scan_type": "bogus"}
    resp = client.post("/scans", headers=HDR, json=payload)
    assert resp.status_code == 400


def test_sast_and_sca_scans_for_same_commit_dont_collide(client, project_id):
    sast = client.post(
        "/scans", headers=HDR, json={"project_id": project_id, "commit_sha": "shared-sha"}
    ).json()
    sca = client.post(
        "/scans",
        headers=HDR,
        json={"project_id": project_id, "commit_sha": "shared-sha", "scan_type": "sca"},
    ).json()
    assert sast["scan_id"] != sca["scan_id"]

    # Re-posting the same sca payload should reuse the sca scan, not the sast one.
    sca_again = client.post(
        "/scans",
        headers=HDR,
        json={"project_id": project_id, "commit_sha": "shared-sha", "scan_type": "sca"},
    ).json()
    assert sca_again["scan_id"] == sca["scan_id"]
    assert sca_again["reused"] is True


# ===========================================================================
# scan_type=sbom
# ===========================================================================


def test_trigger_sbom_scan_round_trips_scan_type(client, project_id):
    payload = {"project_id": project_id, "commit_sha": "sbom-1", "scan_type": "sbom"}
    created = client.post("/scans", headers=HDR, json=payload).json()
    assert created["scan_id"]

    status_resp = client.get(f"/scans/{created['scan_id']}/status", headers=HDR)
    assert status_resp.status_code == 200
    assert status_resp.json()["scan_type"] == "sbom"
    assert status_resp.json()["status"] == "success"

    listed = client.get(
        "/scans", headers=HDR, params={"project_id": project_id, "scan_type": "sbom"}
    ).json()
    assert any(s["id"] == created["scan_id"] and s["scan_type"] == "sbom" for s in listed)

    sast_listed = client.get(
        "/scans", headers=HDR, params={"project_id": project_id, "scan_type": "sast"}
    ).json()
    assert all(s["id"] != created["scan_id"] for s in sast_listed)


def test_sbom_scan_produces_component_discovery_via_mock_engine(client, project_id):
    payload = {"project_id": project_id, "commit_sha": "sbom-mock", "scan_type": "sbom"}
    created = client.post("/scans", headers=HDR, json=payload).json()

    results = client.get(f"/scans/{created['scan_id']}/results", headers=HDR).json()
    discovery = results["discovery"]
    assert discovery is not None
    assert discovery["component_summary"]["total_components"] > 0
    assert "components" in discovery


def test_sbom_scan_defaults_llm_fields_to_none(client, project_id):
    created = client.post(
        "/scans",
        headers=HDR,
        json={
            "project_id": project_id,
            "commit_sha": "sbom-no-llm",
            "scan_type": "sbom",
            "llm_provider": "ollama",
            "llm_model": "granite-code:8b",
        },
    ).json()
    from app.db import SessionLocal
    from app.models import Scan

    db = SessionLocal()
    try:
        scan = db.get(Scan, created["scan_id"])
        assert scan is not None
        assert scan.llm_provider is None
        assert scan.llm_model is None
    finally:
        db.close()


def test_trigger_sbom_scan_rejected_when_project_disables_sbom(client, project_id):
    resp = client.patch(f"/projects/{project_id}", json={"enable_sbom": False}, headers=HDR)
    assert resp.status_code == 200

    payload = {"project_id": project_id, "commit_sha": "sbom-disabled", "scan_type": "sbom"}
    resp = client.post("/scans", headers=HDR, json=payload)
    assert resp.status_code == 400


def test_sast_sca_and_sbom_scans_for_same_commit_dont_collide(client, project_id):
    sast = client.post(
        "/scans", headers=HDR, json={"project_id": project_id, "commit_sha": "shared-sha-2"}
    ).json()
    sca = client.post(
        "/scans",
        headers=HDR,
        json={"project_id": project_id, "commit_sha": "shared-sha-2", "scan_type": "sca"},
    ).json()
    sbom = client.post(
        "/scans",
        headers=HDR,
        json={"project_id": project_id, "commit_sha": "shared-sha-2", "scan_type": "sbom"},
    ).json()
    assert len({sast["scan_id"], sca["scan_id"], sbom["scan_id"]}) == 3


def test_sbom_export_pdf_and_excel(client, project_id):
    """SBOM scans export through the same /export.pdf and /export.xlsx
    endpoints as SAST/SCA — no dedicated CycloneDX/SPDX export surface."""
    payload = {"project_id": project_id, "commit_sha": "sbom-export", "scan_type": "sbom"}
    created = client.post("/scans", headers=HDR, json=payload).json()
    scan_id = created["scan_id"]

    pdf = client.get(f"/scans/{scan_id}/export.pdf", headers=HDR)
    assert pdf.status_code == 200
    assert pdf.headers["content-type"] == "application/pdf"

    xlsx = client.get(f"/scans/{scan_id}/export.xlsx", headers=HDR)
    assert xlsx.status_code == 200
    assert "spreadsheetml" in xlsx.headers["content-type"]
