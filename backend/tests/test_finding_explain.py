import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.db import init_db
from app.main import app
from app.models import Finding, Project, Scan
from app.services import finding_explain

from tests.auth_helpers import ADMIN_HEADERS  # noqa: E402

HDR = ADMIN_HEADERS


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    settings.use_mock_engine = True
    settings.scan_logs_dir = str(tmp_path / "scan_logs")
    settings.workspaces_dir = str(tmp_path / "workspaces")
    init_db(f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    return TestClient(app)


@pytest.fixture()
def sast_scan(client, monkeypatch):
    from app.services import scan_runner

    monkeypatch.setattr(scan_runner, "execute_scan", lambda scan_id: None)
    project_id = client.post(
        "/projects",
        json={"name": "p", "default_git_url": "https://github.com/o/r.git"},
        headers=HDR,
    ).json()["id"]
    scan_id = client.post("/scans", headers=HDR, json={"project_id": project_id, "commit_sha": "ab"}).json()["scan_id"]
    from app.db import SessionLocal

    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        scan.status = "success"
        scan.metadata_json = {
            "discovery": {"tech_stack": "Java + Spring", "frameworks": ["spring"]},
        }
        finding = Finding(
            scan_id=scan_id,
            severity="HIGH",
            title="SQL injection",
            cwe="CWE-89",
            rule_id="java-sql-string-concat",
            file_path="src/Dao.java",
            line=42,
            snippet="sql = \"SELECT * FROM t WHERE id=\" + id;",
            verdict="true_positive",
            verdict_reason="concatenation",
            ai_fix="Use PreparedStatement",
        )
        db.add(finding)
        db.commit()
        fid = finding.id
    finally:
        db.close()
    return scan_id, fid, project_id


def test_safe_workspace_rejects_traversal(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    assert finding_explain._safe_workspace_file(root, "../outside") is None
    assert finding_explain._safe_workspace_file(root, "/etc/passwd") is None


def test_build_context_masks_secrets_in_snippet(sast_scan, monkeypatch):
    from app.db import SessionLocal

    scan_id, fid, project_id = sast_scan
    db = SessionLocal()
    try:
        finding = db.get(Finding, fid)
        scan = db.get(Scan, scan_id)
        project = db.get(Project, project_id)

        def fake_mask(text: str) -> str:
            return text.replace("password123", "[REDACTED]")

        monkeypatch.setattr(finding_explain.secret_masking, "mask_text", fake_mask)
        finding.snippet = 'password = "password123"'
        ctx = finding_explain.build_finding_context(db, scan, finding, project)
        assert "[REDACTED]" in ctx
        assert "password123" not in ctx
    finally:
        db.close()


def test_explain_stream_mocked(client, sast_scan, monkeypatch):
    scan_id, fid, _ = sast_scan
    monkeypatch.setattr(finding_explain, "preflight_error", lambda model=None: None)
    seen = {}

    def fake_stream(_prompt: str, model=None, **_kwargs):
        seen["model"] = model
        yield "thinking", "reasoning"
        yield "response", "## Issue\nBad SQL"

    monkeypatch.setattr(finding_explain, "stream_explain", fake_stream)

    with client.stream(
        "POST",
        f"/scans/{scan_id}/findings/{fid}/explain/stream",
        headers=HDR,
        json={"messages": [], "model": "gpt-oss:120b"},
    ) as resp:
        assert resp.status_code == 200
        body = "".join(resp.iter_text())
    assert "event: meta" in body and "gpt-oss:120b" in body
    assert "event: thinking" in body
    assert "event: chunk" in body
    assert "event: done" in body
    assert "Bad SQL" in body
    assert seen["model"] == "gpt-oss:120b"


def test_explain_defaults_to_configured_model(client, sast_scan, monkeypatch):
    scan_id, fid, _ = sast_scan
    monkeypatch.setattr(finding_explain, "preflight_error", lambda model=None: None)
    seen = {}

    def fake_stream(_prompt: str, model=None, **_kwargs):
        seen["model"] = model
        yield "response", "ok"

    monkeypatch.setattr(finding_explain, "stream_explain", fake_stream)
    with client.stream(
        "POST", f"/scans/{scan_id}/findings/{fid}/explain/stream", headers=HDR, json={"messages": []}
    ) as resp:
        "".join(resp.iter_text())
    assert seen["model"] == settings.sast_explain_ollama_model


def test_think_tags_in_answer_move_to_thinking_across_chunk_boundaries():
    splitter = finding_explain._ThinkTagSplitter()
    out = []
    for chunk in ["<thi", "nk>plan the ", "answer</th", "ink>## Issue\n", "SQL"]:
        out.extend(splitter.feed(chunk))
    out.extend(splitter.flush())
    thinking = "".join(t for k, t in out if k == "thinking")
    response = "".join(t for k, t in out if k == "response")
    assert thinking == "plan the answer"
    assert response == "## Issue\nSQL"


def test_answer_without_think_tags_is_unchanged():
    splitter = finding_explain._ThinkTagSplitter()
    out = list(splitter.feed("a < b and x <t")) + list(splitter.flush())
    assert "".join(t for _, t in out) == "a < b and x <t"
    assert all(k == "response" for k, _ in out)


def test_models_endpoint_lists_pulled_models(client, sast_scan, monkeypatch):
    scan_id, _, _ = sast_scan
    monkeypatch.setattr(finding_explain, "list_models", lambda: (["gpt-oss:120b", "gpt-oss:20b"], None))
    resp = client.get(f"/scans/{scan_id}/explain/models", headers=HDR)
    assert resp.status_code == 200
    body = resp.json()
    assert body["provider"] == "ollama"
    assert body["default_model"] == settings.sast_explain_ollama_model
    assert body["models"] == ["gpt-oss:120b", "gpt-oss:20b"]
    assert body["error"] is None
    assert body["no_think"] == []


def test_offered_netra_models_lead_the_list_when_pulled():
    assert finding_explain.merge_explain_models(
        ["phi4-mini:3.8b", "gemma4:12b", "gpt-oss:20b", "qwen2.5-coder:14b"]
    ) == ["gpt-oss:20b", "gemma4:12b", "phi4-mini:3.8b", "qwen2.5-coder:14b"]


def test_offered_netra_models_appear_even_if_not_pulled():
    assert finding_explain.merge_explain_models(["phi4-mini:3.8b"]) == [
        "gpt-oss:20b",
        "gemma4:12b",
        "phi4-mini:3.8b",
    ]


def test_gemma_is_listed_as_no_think(client, sast_scan, monkeypatch):
    scan_id, _, _ = sast_scan
    monkeypatch.setattr(finding_explain, "list_models", lambda: (["gpt-oss:20b", "gemma4:12b"], None))
    body = client.get(f"/scans/{scan_id}/explain/models", headers=HDR).json()
    assert body["models"] == ["gpt-oss:20b", "gemma4:12b"]
    assert body["no_think"] == ["gemma4:12b"]


def test_stream_explain_drops_thinking_when_the_model_has_thinking_off(monkeypatch):
    class FakeAdapter:
        reasoning = False

        def stream(self, *_a, **_k):
            yield "thinking", "should not leak", None
            yield "response", "<think>scratch</think>## Issue\nSQL", None

    monkeypatch.setattr(finding_explain, "_adapter", lambda _model: FakeAdapter())
    out = list(finding_explain.stream_explain("prompt", "gemma4:12b"))
    assert out == [("response", "## Issue\nSQL")]


def test_explain_404_wrong_finding(client, sast_scan):
    scan_id, _, _ = sast_scan
    resp = client.post(
        f"/scans/{scan_id}/findings/00000000-0000-4000-8000-000000000099/explain/stream",
        headers=HDR,
        json={"messages": []},
    )
    assert resp.status_code == 404


def test_explain_rejects_dast_scan(client, monkeypatch):
    from app.db import SessionLocal
    from app.services import scan_runner

    monkeypatch.setattr(scan_runner, "execute_scan", lambda scan_id: None)
    project_id = client.post(
        "/projects",
        json={"name": "dast-p", "default_git_url": "https://example.com"},
        headers=HDR,
    ).json()["id"]
    scan_id = client.post(
        "/scans",
        headers=HDR,
        json={"project_id": project_id, "commit_sha": "dast1"},
    ).json()["scan_id"]
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        scan.scan_type = "dast"
        finding = Finding(scan_id=scan_id, severity="HIGH", title="XSS", verdict="true_positive")
        db.add(finding)
        db.commit()
        db.refresh(scan)
        fid = finding.id
    finally:
        db.close()
    resp = client.post(
        f"/scans/{scan_id}/findings/{fid}/explain/stream",
        headers=HDR,
        json={"messages": []},
    )
    assert resp.status_code == 422


def test_jira_purpose_uses_the_jira_prompt_and_is_allowed_on_dast(client, sast_scan, monkeypatch):
    scan_id, fid, _ = sast_scan
    monkeypatch.setattr(finding_explain, "preflight_error", lambda model=None: None)
    seen = {}

    def fake_stream(prompt, model=None, system=None, **_kwargs):
        seen["system"] = system
        seen["prompt"] = prompt
        seen["model"] = model
        yield "response", "## Summary\nSQL injection in Dao"

    monkeypatch.setattr(finding_explain, "stream_explain", fake_stream)
    with client.stream(
        "POST",
        f"/scans/{scan_id}/findings/{fid}/explain/stream",
        headers=HDR,
        json={"messages": [], "purpose": "jira"},
    ) as resp:
        assert resp.status_code == 200
        body = "".join(resp.iter_text())
    assert "## Summary" in body
    assert "Write a Jira ticket" in seen["prompt"]
    assert seen["system"] == finding_explain.system_prompt("jira")
    assert "## Summary" in seen["system"]


def test_jira_purpose_is_allowed_on_a_dast_finding(client, monkeypatch):
    from app.db import SessionLocal
    from app.services import scan_runner

    monkeypatch.setattr(scan_runner, "execute_scan", lambda scan_id: None)
    monkeypatch.setattr(finding_explain, "preflight_error", lambda model=None: None)
    monkeypatch.setattr(
        finding_explain,
        "stream_explain",
        lambda *_a, **_k: iter([("response", "## Summary\nXSS")]),
    )
    project_id = client.post(
        "/projects",
        json={"name": "dast-jira", "default_git_url": "https://example.com"},
        headers=HDR,
    ).json()["id"]
    scan_id = client.post(
        "/scans", headers=HDR, json={"project_id": project_id, "commit_sha": "dast-jira"}
    ).json()["scan_id"]
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        scan.scan_type = "dast"
        finding = Finding(scan_id=scan_id, severity="HIGH", title="XSS", verdict="true_positive")
        db.add(finding)
        db.commit()
        fid = finding.id
    finally:
        db.close()
    with client.stream(
        "POST",
        f"/scans/{scan_id}/findings/{fid}/explain/stream",
        headers=HDR,
        json={"messages": [], "purpose": "jira"},
    ) as resp:
        assert resp.status_code == 200
        assert "XSS" in "".join(resp.iter_text())


def test_jira_system_prompt_file_is_loaded():
    text = finding_explain.system_prompt("jira")
    for heading in ("## Summary", "## Issue type", "## Priority", "## Labels", "## Description"):
        assert heading in text
    assert finding_explain.system_prompt("explain") != text