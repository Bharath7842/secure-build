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


def test_create_duplicate_project_name_keeps_the_name(client):
    first = client.post("/projects", json=_payload(name="duplicate"), headers=AUTH_HEADER).json()
    resp = client.post("/projects", json=_payload(name="duplicate"), headers=AUTH_HEADER)
    assert resp.status_code == 201
    second = resp.json()
    assert first["name"] == second["name"] == "duplicate"
    assert second["id"] != first["id"]


def test_rename_onto_existing_name_is_accepted(client):
    client.post("/projects", json=_payload(name="taken-name"), headers=AUTH_HEADER)
    other = client.post("/projects", json=_payload(name="other-name"), headers=AUTH_HEADER).json()
    resp = client.patch(
        f"/projects/{other['id']}", json={"name": "taken-name"}, headers=AUTH_HEADER
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "taken-name"


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


def test_project_accepts_claude_cli_provider(client):
    resp = client.post(
        "/projects",
        json=_payload(name="claude-cli", llm_provider="claude_cli", llm_model="sonnet"),
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 201
    assert resp.json()["llm_provider"] == "claude_cli"


def test_llm_api_key_is_write_only(client):
    resp = client.post(
        "/projects",
        json=_payload(
            name="openai-compat",
            llm_provider="openai_compat",
            llm_model="qwen2.5-coder-32b",
            llm_base_url="http://localhost:8000/v1",
            llm_api_key="sk-secret-value",
        ),
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["llm_provider"] == "openai_compat"
    assert body["llm_base_url"] == "http://localhost:8000/v1"
    assert body["llm_api_key_set"] is True
    assert "sk-secret-value" not in resp.text
    assert "llm_api_key" not in body

    project_id = body["id"]
    # Omitting the key keeps it.
    kept = client.patch(f"/projects/{project_id}", json={"llm_model": "other"}, headers=AUTH_HEADER)
    assert kept.json()["llm_api_key_set"] is True
    # An empty string clears it.
    cleared = client.patch(f"/projects/{project_id}", json={"llm_api_key": ""}, headers=AUTH_HEADER)
    assert cleared.json()["llm_api_key_set"] is False


def test_new_project_has_no_ollama_fallback(client):
    body = client.post("/projects", json=_payload(name="fallback"), headers=AUTH_HEADER).json()
    assert body["fallback_llm_provider"] == "none"


@pytest.mark.parametrize("field,value", [
    ("llm_provider", "openai"),
    ("fallback_llm_provider", "gpt"),
])
def test_project_rejects_unknown_llm_settings(client, field, value):
    resp = client.post("/projects", json=_payload(name=f"bad-{field}", **{field: value}), headers=AUTH_HEADER)
    assert resp.status_code == 422


def test_old_databases_lose_the_removed_data_policy_column(tmp_path):
    """A database created before the code-sharing setting was removed loses its column on startup."""
    from sqlalchemy import create_engine, inspect, text

    from app.db import init_db

    url = f"sqlite:///{(tmp_path / 'old.db').as_posix()}"
    init_db(url)
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE projects ADD COLUMN llm_data_policy VARCHAR(20) DEFAULT 'allow_external'"))
        conn.execute(text("ALTER TABLE scans ADD COLUMN llm_data_policy VARCHAR(20)"))
    init_db(url)  # restart
    inspector = inspect(engine)
    assert "llm_data_policy" not in {c["name"] for c in inspector.get_columns("projects")}
    assert "llm_data_policy" not in {c["name"] for c in inspector.get_columns("scans")}


def test_startup_moves_old_granite_fallback_to_the_instruct_tag(tmp_path):
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import Session

    from app.db import init_db
    from app.models import Project

    url = f"sqlite:///{(tmp_path / 'old.db').as_posix()}"
    init_db(url)
    engine = create_engine(url)
    with Session(engine) as db:
        db.add(Project(
            id="p1", name="old", default_git_url="https://example.com/r.git",
            fallback_llm_provider="ollama", fallback_llm_model="granite-code:3b",
        ))
        db.commit()
    init_db(url)
    with engine.begin() as conn:
        model = conn.execute(text("SELECT fallback_llm_model FROM projects WHERE id='p1'")).scalar()
    assert model == "granite-code:3b-instruct"
