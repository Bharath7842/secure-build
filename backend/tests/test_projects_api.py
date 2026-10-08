import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.db import init_db
from app.main import app

AUTH_HEADER = {"Authorization": f"Bearer {settings.sast_api_token}"}


@pytest.fixture()
def client(tmp_path):
    url = f"sqlite:///{(tmp_path / 'test.db').as_posix()}"
    init_db(url)
    # Do NOT use `with TestClient(app)` here: entering the context triggers
    # the app's startup event, which calls init_db() with no args and would
    # reset the engine back to the production database_url, undoing the
    # tmp_path db we just set up above.
    return TestClient(app)


def _payload(**overrides):
    payload = {
        "name": "demo-project",
        "default_git_url": "https://github.com/org/repo.git",
        "owasp_mode": "top10",
    }
    payload.update(overrides)
    return payload


def test_create_project_prefills_owasp_top10(client):
    resp = client.post("/projects", json=_payload(), headers=AUTH_HEADER)
    assert resp.status_code == 201
    body = resp.json()
    assert len(body["owasp_urls"]) >= 10
    assert all(url.startswith("https://") for url in body["owasp_urls"])
    assert len(body["nvd_urls"]) >= 10
    assert all(url.startswith("https://") for url in body["nvd_urls"])
    assert all("nvd.nist.gov" in url for url in body["nvd_urls"])
    assert any("CVE-2021-44228" in url for url in body["nvd_urls"])
    assert body["nvd_mode"] == "top10"
    keys = [s["key"] for s in body["reference_sources"]]
    assert "OWASP" in keys and "NVD" in keys


def test_create_project_prefills_nvd_top15_from_nvd_mode(client):
    resp = client.post(
        "/projects",
        json=_payload(name="nvd-top15", nvd_mode="top15"),
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["nvd_mode"] == "top15"
    assert len(body["nvd_urls"]) >= 15
    assert any("CVE-2021-45046" in url for url in body["nvd_urls"])


def test_create_project_with_mitre_and_cisa_sources(client):
    resp = client.post(
        "/projects",
        json=_payload(
            name="multi-src",
            reference_sources=[
                {"key": "OWASP", "name": "OWASP", "mode": "top10", "urls": []},
                {"key": "MITRE", "name": "MITRE", "mode": "top10", "urls": []},
                {"key": "CISA", "name": "CISA", "mode": "top10", "urls": []},
            ],
        ),
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 201
    body = resp.json()
    keys = [s["key"] for s in body["reference_sources"]]
    assert keys == ["OWASP", "MITRE", "CISA"]
    mitre = next(s for s in body["reference_sources"] if s["key"] == "MITRE")
    cisa = next(s for s in body["reference_sources"] if s["key"] == "CISA")
    assert len(mitre["urls"]) >= 5
    assert any("mitre.org" in u for u in mitre["urls"])
    assert len(cisa["urls"]) >= 5
    assert any("cisa.gov" in u for u in cisa["urls"])


def test_create_project_defaults_llm_provider_to_bedrock_haiku(client):
    resp = client.post("/projects", json=_payload(name="llm-default"), headers=AUTH_HEADER)
    assert resp.status_code == 201
    body = resp.json()
    assert "rule_scope" not in body
    assert body["llm_provider"] == "bedrock"
    assert "haiku" in body["llm_model"].lower()


def test_create_project_with_ollama_llm_provider(client):
    resp = client.post(
        "/projects",
        json=_payload(name="llm-ollama", llm_provider="ollama", llm_model="granite-code:3b"),
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["llm_provider"] == "ollama"
    assert body["llm_model"] == "granite-code:3b"


def test_patch_updates_llm_provider_and_model(client):
    created = client.post(
        "/projects", json=_payload(name="llm-patch"), headers=AUTH_HEADER
    ).json()
    assert created["llm_provider"] == "bedrock"

    resp = client.patch(
        f"/projects/{created['id']}",
        json={"llm_provider": "ollama", "llm_model": "granite-code:3b"},
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["llm_provider"] == "ollama"
    assert body["llm_model"] == "granite-code:3b"


def test_create_project_without_auth_returns_401(client):
    resp = client.post("/projects", json=_payload(name="no-auth"))
    assert resp.status_code == 401


def test_create_duplicate_project_name_returns_409(client):
    client.post("/projects", json=_payload(name="duplicate"), headers=AUTH_HEADER)
    resp = client.post("/projects", json=_payload(name="duplicate"), headers=AUTH_HEADER)
    assert resp.status_code == 409
    assert resp.json()["detail"] == "Project name already exists"


def test_list_projects_returns_created_project(client):
    client.post("/projects", json=_payload(name="list-me"), headers=AUTH_HEADER)
    resp = client.get("/projects", headers=AUTH_HEADER)
    assert resp.status_code == 200
    names = [p["name"] for p in resp.json()]
    assert "list-me" in names


def test_get_project_by_id_and_404_for_unknown(client):
    created = client.post("/projects", json=_payload(name="get-me"), headers=AUTH_HEADER).json()

    resp = client.get(f"/projects/{created['id']}", headers=AUTH_HEADER)
    assert resp.status_code == 200
    assert resp.json()["id"] == created["id"]

    missing = client.get("/projects/does-not-exist", headers=AUTH_HEADER)
    assert missing.status_code == 404


def test_patch_updates_owasp_urls_and_max_files(client):
    created = client.post("/projects", json=_payload(name="patch-me"), headers=AUTH_HEADER).json()

    resp = client.patch(
        f"/projects/{created['id']}",
        json={
            "owasp_urls": ["https://example.com/custom"],
            "max_files_to_scan": 25,
        },
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["owasp_urls"] == ["https://example.com/custom"]
    assert body["max_files_to_scan"] == 25


def test_create_project_without_git_url_for_dast_only_use(client):
    """A project meant only for DAST scans has no repository — the name
    alone must be enough to create it."""
    resp = client.post(
        "/projects",
        json={"name": "dast-only-project"},
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 201
    assert resp.json()["default_git_url"] == ""
