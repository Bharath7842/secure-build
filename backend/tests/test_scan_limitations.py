"""Scan limitations catalog and configuration tests."""

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.db import init_db
from app.defaults.scan_limitations import SCAN_LIMITATIONS, limitations_as_dicts
from app.main import app

HDR = {"Authorization": f"Bearer {settings.sast_api_token}"}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    settings.use_mock_engine = True
    settings.scan_logs_dir = str(tmp_path / "scan_logs")
    url = f"sqlite:///{(tmp_path / 'test.db').as_posix()}"
    init_db(url)
    return TestClient(app)


def test_scan_limitations_structure():
    """Verify all limitations have required fields."""
    assert len(SCAN_LIMITATIONS) >= 7
    for lim in SCAN_LIMITATIONS:
        assert lim.id
        assert isinstance(lim.enabled_by_default, bool)
        assert lim.category in ("engine-cap", "analysis-check", "security-pattern")
        assert lim.title
        assert lim.description


def test_scan_limitations_expected_ids():
    """Verify expected limitation IDs exist."""
    ids = {lim.id for lim in SCAN_LIMITATIONS}
    expected = {
        "bedrock-spend-cutoff",
        "ast-structural-check",
        "dependency-manifest-scan",
        "file-categorization",
        "module-mapping",
        "jwt-sessionstorage-pattern",
        "auth-token-hardcoding",
        "regex-gated-triage",
        "absence-checks-llm-only",
        "inter-file-call-graph",
        "runtime-derived-regex",
        "cwe-less-findings-suppressed",
        "https-enforced-suppress-http",
        "low-confidence-fp-suppressed",
        "vendored-minified-files-skipped",
        "sbom-direct-deps-only",
        "sbom-license-best-effort",
        "sbom-llm-enrichment-best-effort",
    }
    assert expected.issubset(ids)


def test_limitations_as_dicts_for_api():
    rows = limitations_as_dicts()
    assert len(rows) == len(SCAN_LIMITATIONS)
    assert all("id" in r and "title" in r for r in rows)


def test_list_scan_limitations_api(client):
    resp = client.get("/scan-limitations", headers=HDR)
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == len(SCAN_LIMITATIONS)
    ids = {r["id"] for r in rows}
    assert "jwt-sessionstorage-pattern" in ids
    assert "regex-gated-triage" in ids


def test_list_scan_limitations_requires_auth(client):
    resp = client.get("/scan-limitations")
    assert resp.status_code == 401


def test_update_project_limitations_api(client):
    """Test that PATCH /projects/{id}/limitations updates the config."""
    from app.models import Project

    # Create a test project
    resp = client.post(
        "/projects",
        json={
            "name": "test-project",
            "description": "A test",
            "default_git_url": "https://github.com/test/repo.git",
            "default_branch": "main",
        },
        headers=HDR,
    )
    assert resp.status_code == 201
    project = resp.json()
    project_id = project["id"]

    # Initially limitations_config should be None (all enabled by default)
    assert project.get("limitations_config") is None

    # Update to enable only a subset
    enabled_ids = ["bedrock-spend-cutoff", "regex-gated-triage"]
    resp = client.patch(
        f"/projects/{project_id}/limitations",
        json={"enabled_ids": enabled_ids},
        headers=HDR,
    )
    assert resp.status_code == 200
    updated = resp.json()
    assert updated["limitations_config"] is not None
    assert updated["limitations_config"]["bedrock-spend-cutoff"] is True
    assert updated["limitations_config"]["regex-gated-triage"] is True
    assert updated["limitations_config"]["jwt-sessionstorage-pattern"] is False
    assert updated["limitations_config"]["ast-structural-check"] is False


def test_update_project_limitations_invalid_id(client):
    """Test that invalid limitation IDs are rejected."""
    from app.models import Project

    # Create a test project
    resp = client.post(
        "/projects",
        json={
            "name": "test-project-2",
            "description": "A test",
            "default_git_url": "https://github.com/test/repo.git",
            "default_branch": "main",
        },
        headers=HDR,
    )
    project = resp.json()
    project_id = project["id"]

    # Try to enable a nonexistent limitation
    resp = client.patch(
        f"/projects/{project_id}/limitations",
        json={"enabled_ids": ["invalid-id", "bedrock-spend-cutoff"]},
        headers=HDR,
    )
    assert resp.status_code == 400
    assert "Unknown limitation IDs" in resp.json()["detail"]
