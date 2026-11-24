"""`POST /ci/scan`: a pipeline finds (or creates) its project from the repository URL and scans.

Mock engine throughout (no git, no network): the clone path is covered by unit tests of the
helpers it uses (`authenticated_clone_url`, `ensure_workspace`, `_clone_credentials`).
"""

import threading

import pytest
from fastapi.testclient import TestClient

from app import db as app_db
from app.auth.principal import Principal
from app.authz.catalog import CI_SERVICE_PERMISSIONS
from app.config import settings
from app.db import init_db
from app.main import app
from app.models import Project, Scan
from app.routers import ci as ci_router
from app.services import ci_credentials, git_workspace, scan_runner
from app.services.repo_key import normalize_repo_key, repo_display_name
from tests.auth_helpers import ADMIN_HEADERS, CI_HEADERS

REPO = "https://gitlab.example.com/Group/My-Repo"
JOB_TOKEN = "glcbt-64_SuperSecretJobToken"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    monkeypatch.setattr(settings, "use_mock_engine", True)
    monkeypatch.setattr(settings, "scan_logs_dir", str(tmp_path / "scan_logs"))
    init_db(f"sqlite:///{(tmp_path / 'ci.db').as_posix()}")
    return TestClient(app)


def _post(client, **body):
    body.setdefault("repo_url", f"{REPO}.git")
    body.setdefault("branch", "main")
    body.setdefault("commit_sha", "a" * 40)
    return client.post("/ci/scan", headers=CI_HEADERS, json=body)


def _projects():
    with app_db.SessionLocal() as db:
        return db.query(Project).all()


# ---- find or create ---------------------------------------------------------------------


def test_first_request_creates_the_project_and_scans(client):
    resp = _post(client)
    assert resp.status_code == 202, resp.text
    data = resp.json()
    assert data["project_created"] is True
    assert data["project_name"] == "Group/My-Repo"
    [scan] = data["scans"]
    assert scan["scan_type"] == "sast"
    assert scan["version"] == 1
    assert scan["reused"] is False
    assert scan["scan_url"].endswith(f"/scans/{scan['scan_id']}")
    [project] = _projects()
    assert project.id == data["project_id"]
    assert project.default_git_url == f"{REPO}.git"
    assert project.default_branch == "main"
    assert project.repo_key == "gitlab.example.com/group/my-repo"


def test_same_commit_again_reuses_the_scan(client):
    first = _post(client).json()
    second = _post(client).json()
    assert second["project_created"] is False
    assert second["project_id"] == first["project_id"]
    assert second["scans"][0]["scan_id"] == first["scans"][0]["scan_id"]
    assert second["scans"][0]["reused"] is True
    assert len(_projects()) == 1


def test_new_commit_is_the_next_version_of_the_same_project(client):
    first = _post(client, commit_sha="a" * 40).json()
    second = _post(client, commit_sha="b" * 40).json()
    assert second["project_id"] == first["project_id"]
    assert second["scans"][0]["version"] == 2
    assert second["scans"][0]["scan_id"] != first["scans"][0]["scan_id"]


def test_force_starts_a_fresh_scan_of_the_same_commit(client):
    first = _post(client).json()
    again = _post(client, force=True).json()
    assert again["scans"][0]["scan_id"] != first["scans"][0]["scan_id"]
    assert again["scans"][0]["reused"] is False


@pytest.mark.parametrize(
    "spelling",
    [
        "https://gitlab.example.com/group/my-repo",
        "https://GitLab.Example.com/Group/My-Repo.git/",
        "git@gitlab.example.com:group/my-repo.git",
        "https://oauth2:secret@gitlab.example.com/group/my-repo.git",
    ],
)
def test_every_spelling_of_a_repository_is_one_project(client, spelling):
    first = _post(client).json()
    again = _post(client, repo_url=spelling).json()
    assert again["project_id"] == first["project_id"]
    assert len(_projects()) == 1


def test_a_project_made_in_the_app_is_found_by_url(client):
    made = client.post(
        "/projects",
        headers=ADMIN_HEADERS,
        json={"name": "Hand made", "default_git_url": "https://gitlab.example.com/group/my-repo.git"},
    )
    assert made.status_code == 201
    resp = _post(client).json()
    assert resp["project_created"] is False
    assert resp["project_id"] == made.json()["id"]


def test_branch_is_a_scan_parameter_not_a_new_project(client):
    main = _post(client, branch="main", commit_sha="a" * 40).json()
    feature = _post(client, branch="feature/x", commit_sha="b" * 40).json()
    assert feature["project_id"] == main["project_id"]
    with app_db.SessionLocal() as db:
        branches = {s.branch for s in db.query(Scan).all()}
    assert branches == {"main", "feature/x"}


def test_credentials_in_the_repo_url_are_not_stored(client):
    _post(client, repo_url="https://oauth2:hunter2@gitlab.example.com/group/my-repo.git")
    [project] = _projects()
    assert "hunter2" not in project.default_git_url
    with app_db.SessionLocal() as db:
        assert all("hunter2" not in s.git_url for s in db.query(Scan).all())


def test_concurrent_first_requests_create_one_project(client):
    principal = Principal(kind="service", permissions=CI_SERVICE_PERMISSIONS)
    barrier = threading.Barrier(4)
    results: list[tuple[str, bool]] = []

    def worker():
        barrier.wait()
        with app_db.SessionLocal() as db:
            project, created = ci_router._find_or_create_project(
                db, principal, f"{REPO}.git", "gitlab.example.com/group/my-repo", "main"
            )
            results.append((project.id, created))

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len({pid for pid, _ in results}) == 1
    assert sum(1 for _, created in results if created) == 1
    assert len(_projects()) == 1


# ---- scan types and options -------------------------------------------------------------


def test_several_scan_types_in_one_request(client):
    resp = _post(client, scan_types=["sast", "sca", "sbom"])
    assert resp.status_code == 202, resp.text
    assert [s["scan_type"] for s in resp.json()["scans"]] == ["sast", "sca", "sbom"]
    assert len({s["scan_id"] for s in resp.json()["scans"]}) == 3


def test_unknown_scan_type_is_rejected(client):
    resp = _post(client, scan_types=["dast"])
    assert resp.status_code == 422
    assert _projects() == []


def test_a_disabled_scan_type_starts_nothing(client):
    made = client.post(
        "/projects",
        headers=ADMIN_HEADERS,
        json={
            "name": "No SCA",
            "default_git_url": f"{REPO}.git",
            "enable_sca": False,
        },
    ).json()
    resp = _post(client, scan_types=["sast", "sca"])
    assert resp.status_code == 400
    assert "SCA" in resp.json()["detail"]
    with app_db.SessionLocal() as db:
        assert db.query(Scan).filter(Scan.project_id == made["id"]).count() == 0


def test_options_apply_to_the_scan_and_leave_the_project_alone(client):
    resp = _post(client, use_llm=True, llm_provider="ollama", llm_model="granite-code:3b", path="services/api")
    assert resp.status_code == 202, resp.text
    scan_id = resp.json()["scans"][0]["scan_id"]
    with app_db.SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        project = db.get(Project, resp.json()["project_id"])
        assert scan.llm_provider == "ollama"
        assert scan.llm_model == "granite-code:3b"
        assert scan.metadata_json["repo_path"] == "services/api"
        assert scan.metadata_json["source"] == "ci"
        assert project.llm_provider == "bedrock"
        assert not project.monorepo_path


def test_no_llm_unless_asked(client):
    scan_id = _post(client).json()["scans"][0]["scan_id"]
    with app_db.SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        assert scan.metadata_json["use_llm"] is False
        assert scan.llm_provider is None


# ---- authentication ---------------------------------------------------------------------


def test_requires_a_token(client):
    resp = client.post("/ci/scan", json={"repo_url": f"{REPO}.git"})
    assert resp.status_code == 401
    bad = client.post(
        "/ci/scan", headers={"Authorization": "Bearer wrong"}, json={"repo_url": f"{REPO}.git"}
    )
    assert bad.status_code == 401
    assert _projects() == []


# ---- the job token ----------------------------------------------------------------------


def test_job_token_is_held_in_memory_and_never_stored_or_returned(client):
    resp = _post(client, job_token=JOB_TOKEN)
    assert resp.status_code == 202, resp.text
    assert JOB_TOKEN not in resp.text
    scan_id = resp.json()["scans"][0]["scan_id"]
    assert ci_credentials.get_job_token(scan_id) == JOB_TOKEN
    with app_db.SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        assert JOB_TOKEN not in repr(scan.metadata_json)
        assert JOB_TOKEN not in scan.git_url
        assert JOB_TOKEN not in (scan.message or "")
        project = db.get(Project, resp.json()["project_id"])
        assert not project.git_access_token
        assert project.git_provider is None
    # A pipeline cannot smuggle a token into the stored metadata either.
    other = _post(client, commit_sha="c" * 40, metadata={"job_token": "x", "pipeline_url": "https://p"})
    other_scan = other.json()["scans"][0]["scan_id"]
    with app_db.SessionLocal() as db:
        meta = db.get(Scan, other_scan).metadata_json
        assert "job_token" not in meta
        assert meta["pipeline_url"] == "https://p"


def test_job_token_validation_error_does_not_echo_it(client):
    resp = _post(client, job_token=JOB_TOKEN, scan_types=["nope"])
    assert resp.status_code == 422
    assert JOB_TOKEN not in resp.text


def test_runner_prefers_the_job_token_over_the_project_connection(client):
    ci_credentials.set_job_token("scan-1", JOB_TOKEN)

    class FakeProject:
        git_provider = "gitlab"
        git_access_token = "oauth-token"
        git_token_expires_at = None
        git_refresh_token = None

    assert scan_runner._clone_credentials("scan-1", FakeProject()) == (
        git_workspace.GITLAB_JOB_PROVIDER,
        JOB_TOKEN,
    )
    assert scan_runner._clone_credentials("scan-2", FakeProject()) == ("gitlab", "oauth-token")
    ci_credentials.clear("scan-1")
    assert ci_credentials.get_job_token("scan-1") is None


def test_job_token_expires(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(ci_credentials.time, "monotonic", lambda: now[0])
    ci_credentials.set_job_token("scan-x", JOB_TOKEN)
    assert ci_credentials.get_job_token("scan-x") == JOB_TOKEN
    now[0] += ci_credentials.TTL_SECONDS + 1
    assert ci_credentials.get_job_token("scan-x") is None


# ---- git helpers ------------------------------------------------------------------------


def test_job_token_clone_url_uses_gitlab_ci_token_user():
    url = git_workspace.authenticated_clone_url(
        f"{REPO}.git", git_workspace.GITLAB_JOB_PROVIDER, "glcbt-64_a/b"
    )
    assert url == "https://gitlab-ci-token:glcbt-64_a%2Fb@gitlab.example.com/Group/My-Repo.git"
    assert git_workspace.redact_git_url(url) == f"{REPO}.git"


def test_oauth_clone_urls_are_unchanged():
    assert (
        git_workspace.authenticated_clone_url(f"{REPO}.git", "gitlab", "tok")
        == "https://oauth2:tok@gitlab.example.com/Group/My-Repo.git"
    )
    assert (
        git_workspace.authenticated_clone_url("https://github.com/o/r.git", "github", "tok")
        == "https://x-access-token:tok@github.com/o/r.git"
    )


def test_workspace_does_not_keep_the_job_token(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "workspaces_dir", str(tmp_path))
    (tmp_path / "proj" / ".git").mkdir(parents=True)
    calls: list[list[str]] = []
    monkeypatch.setattr(git_workspace, "_git", lambda args, cwd=None: calls.append(args) or "")

    git_workspace.ensure_workspace(
        "proj", f"{REPO}.git", "main", "a" * 40, git_workspace.GITLAB_JOB_PROVIDER, JOB_TOKEN
    )

    set_urls = [c[-1] for c in calls if c[:3] == ["remote", "set-url", "origin"]]
    assert JOB_TOKEN in set_urls[0]  # fetched with it
    assert set_urls[-1] == f"{REPO}.git"  # and left without it
    assert calls[-1][:3] == ["remote", "set-url", "origin"]


def test_workspace_lock_makes_scans_of_one_project_take_turns():
    active = 0
    peak = 0
    guard = threading.Lock()

    def scan(project_id):
        nonlocal active, peak
        with git_workspace.workspace_lock(project_id):
            with guard:
                active += 1
                peak = max(peak, active)
            threading.Event().wait(0.02)
            with guard:
                active -= 1

    threads = [threading.Thread(target=scan, args=("same",)) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert peak == 1

    peak = active = 0
    other = [threading.Thread(target=scan, args=(f"p{i}",)) for i in range(3)]
    for t in other:
        t.start()
    for t in other:
        t.join()
    assert peak >= 2  # different projects do not wait for each other


# ---- repo key ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url, key",
    [
        ("https://gitlab.com/g/r.git", "gitlab.com/g/r"),
        ("https://GitLab.com/G/R/", "gitlab.com/g/r"),
        ("git@gitlab.com:g/sub/r.git", "gitlab.com/g/sub/r"),
        ("ssh://git@gitlab.com/g/r.git", "gitlab.com/g/r"),
        ("https://u:p@gitlab.com:8443/g/r.git", "gitlab.com:8443/g/r"),
        ("/tmp/Some/Repo", "tmp/some/repo"),
        ("", None),
        ("   ", None),
    ],
)
def test_normalize_repo_key(url, key):
    assert normalize_repo_key(url) == key


def test_repo_display_name_keeps_case_and_drops_host():
    assert repo_display_name("https://gitlab.com/Group/Sub/Repo.git") == "Group/Sub/Repo"
    assert repo_display_name("git@gitlab.com:Group/Repo.git") == "Group/Repo"


def test_repo_key_follows_the_url_when_a_project_is_edited(client):
    made = client.post(
        "/projects",
        headers=ADMIN_HEADERS,
        json={"name": "p", "default_git_url": "https://gitlab.com/a/b.git"},
    ).json()
    with app_db.SessionLocal() as db:
        assert db.get(Project, made["id"]).repo_key == "gitlab.com/a/b"
    patched = client.patch(
        f"/projects/{made['id']}", headers=ADMIN_HEADERS, json={"default_git_url": "https://gitlab.com/a/c.git"}
    )
    assert patched.status_code == 200
    with app_db.SessionLocal() as db:
        assert db.get(Project, made["id"]).repo_key == "gitlab.com/a/c"
