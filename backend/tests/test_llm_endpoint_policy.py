"""LLM03 guardrails: where a scan may send repository code.

The shared check (`sast_engine/endpoint_policy.py`) with an injected resolver, so
no test touches DNS."""

import sys
from pathlib import Path

import pytest

_ENGINE = Path(__file__).resolve().parents[1] / "sast_engine"
if str(_ENGINE) not in sys.path:
    sys.path.insert(0, str(_ENGINE))

import endpoint_policy  # noqa: E402

pytestmark = pytest.mark.unit

HOSTS = {
    "llm.example.com": ["93.184.216.34"],
    "vllm.corp.internal": ["10.1.2.3"],
    "rebind.example.com": ["10.0.0.5"],
    "meta.example.com": ["169.254.169.254"],
    "dual.example.com": ["93.184.216.34", "10.0.0.9"],
    "v6.example.com": ["2606:2800:220:1:248:1893:25c8:1946"],
    "mapped.example.com": ["::ffff:127.0.0.1"],
    "localhost": ["127.0.0.1"],
}


def resolve(host, _port):
    if host not in HOSTS:
        raise OSError("no such host")
    return [(2, 1, 6, "", (ip, 0)) for ip in HOSTS[host]]


def check(url, **kw):
    return endpoint_policy.check_endpoint(url, resolve=resolve, **kw)


@pytest.mark.parametrize("url", [
    "https://llm.example.com/v1",
    "https://llm.example.com:8443/v1",
    "https://v6.example.com/v1",
    "http://localhost:11434",
    "http://127.0.0.1:8000/v1",
    "http://[::1]:8000/v1",
    "https://never-resolves.example.org/v1",  # unresolvable: nothing to object to yet
])
def test_a_public_https_endpoint_and_a_local_one_are_allowed(url):
    assert check(url) is None


@pytest.mark.parametrize("url, fragment", [
    ("http://llm.example.com/v1", "https"),
    ("ftp://llm.example.com/v1", "http(s)"),
    ("file:///etc/passwd", "http(s)"),
    ("https://user:pw@llm.example.com/v1", "credentials"),
    ("https:///v1", "no host"),
    ("not a url", "http(s)"),
    ("", "http(s)"),
])
def test_scheme_credentials_and_shape_are_checked(url, fragment):
    assert fragment in check(url)


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data",
    "https://169.254.169.254/",
    "http://metadata.google.internal/computeMetadata/v1",
    "https://meta.example.com/v1",               # a name that resolves to the metadata address
    "http://[fe80::1]/v1",
    "http://100.100.100.200/",
    "http://0.0.0.0:8000/v1",
])
def test_metadata_link_local_and_unspecified_addresses_are_never_allowed(url):
    assert check(url) is not None


def test_not_even_an_approved_host_can_be_a_metadata_address():
    assert check("http://169.254.169.254/", allowed_hosts=["169.254.169.254"]) is not None
    assert check("https://meta.example.com/v1", allowed_hosts=["meta.example.com"]) is not None


def test_a_private_address_needs_an_approved_host_and_then_may_use_http():
    assert "approve" in check("https://vllm.corp.internal/v1")
    assert "approve" in check("http://10.1.2.3:8000/v1")
    assert check("http://vllm.corp.internal:8000/v1", allowed_hosts=["vllm.corp.internal"]) is None
    assert check("https://vllm.corp.internal/v1", allowed_hosts=["VLLM.corp.internal"]) is None


def test_an_approved_host_with_a_port_matches_only_that_port():
    approved = ["vllm.corp.internal:8000"]
    assert check("http://vllm.corp.internal:8000/v1", allowed_hosts=approved) is None
    assert check("http://vllm.corp.internal:9000/v1", allowed_hosts=approved) is not None


def test_a_name_that_resolves_to_a_private_address_is_caught_at_call_time():
    # the same name was public when it was configured, private now (DNS rebinding)
    assert "private address" in check("https://rebind.example.com/v1")


def test_one_private_answer_among_public_ones_denies_the_host():
    assert check("https://dual.example.com/v1") is not None


def test_an_ipv4_mapped_ipv6_loopback_is_loopback():
    assert check("http://mapped.example.com/v1") is None
    assert "loopback" in check("http://mapped.example.com/v1", allow_loopback=False)


def test_loopback_can_be_turned_off_for_a_server():
    assert "loopback" in check("http://localhost:11434", allow_loopback=False)
    assert check("http://localhost:11434", allow_loopback=False, allowed_hosts=["localhost"]) is None


# --- the engine refuses before it sends -----------------------------------------------

from unittest.mock import MagicMock  # noqa: E402


@pytest.fixture()
def llm(monkeypatch):
    pytest.importorskip("boto3", reason="llm_client requires boto3")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    import llm_client as module

    return module


def _compat_usage(llm, base_url, **kw):
    return llm.init_usage(
        "openai_compat", "m", provider_options={"openai_compat": {"base_url": base_url, "api_key": "sk-test"}}, **kw,
    )


def test_the_engine_never_posts_to_a_metadata_address(llm, monkeypatch):
    post = MagicMock()
    monkeypatch.setattr(llm.requests, "post", post)
    usage = _compat_usage(llm, "http://169.254.169.254/latest")
    with pytest.raises(Exception, match="metadata|link-local"):
        llm.call_llm("s", "u", usage=usage, step="t", json_mode=True)
    post.assert_not_called()
    assert usage["_counters"]["endpoint_policy"]["denied"] == 1


def test_the_engine_refuses_plain_http_to_a_public_host_but_not_when_approved(llm, monkeypatch):
    post = MagicMock()
    monkeypatch.setattr(llm.requests, "post", post)
    with pytest.raises(Exception, match="https"):
        llm.call_llm("s", "u", usage=_compat_usage(llm, "http://93.184.216.34/v1"), step="t")
    post.assert_not_called()
    response = MagicMock(status_code=200)
    response.json.return_value = {"choices": [{"message": {"content": "{}"}}], "usage": {}}
    post.return_value = response
    approved = _compat_usage(llm, "http://93.184.216.34/v1", endpoint_policy={"allowed_hosts": ["93.184.216.34"]})
    llm.call_llm("s", "u", usage=approved, step="t")
    assert post.call_args.kwargs["allow_redirects"] is False


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_a_redirect_is_not_followed_and_the_prompt_is_not_resent(llm, monkeypatch, status):
    post = MagicMock(return_value=MagicMock(status_code=status, headers={"Location": "https://evil.example/x"}))
    monkeypatch.setattr(llm.requests, "post", post)
    with pytest.raises(Exception, match="redirects are not followed"):
        llm.call_llm("s", "u", usage=_compat_usage(llm, "https://93.184.216.34/v1"), step="t")
    assert post.call_count == 1  # not retried, not followed


def test_ollama_is_held_to_the_same_policy(llm, monkeypatch):
    post = MagicMock()
    monkeypatch.setattr(llm.requests, "post", post)
    monkeypatch.setattr(llm, "OLLAMA_BASE_URL", "http://169.254.169.254:11434")
    with pytest.raises(Exception, match="metadata|link-local"):
        llm.call_llm("s", "u", usage=llm.init_usage("ollama", "m"), step="t", provider="ollama", model="m")
    post.assert_not_called()


def test_bedrock_opus_is_priced_above_sonnet_and_haiku(llm):
    haiku = llm._price_per_mtok("bedrock", "us.anthropic.claude-haiku-4-5-20251001-v1:0")
    sonnet = llm._price_per_mtok("bedrock", "us.anthropic.claude-sonnet-4-5")
    opus = llm._price_per_mtok("bedrock", "us.anthropic.claude-opus-4-1")
    assert haiku < sonnet < opus


# --- the app: who may point a project at which endpoint ------------------------------------

from fastapi.testclient import TestClient  # noqa: E402

from app import db as db_module  # noqa: E402
from app.config import settings  # noqa: E402
from app.db import init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Project, Scan  # noqa: E402
from app.services import agent_bridge, llm_policy, scan_versions  # noqa: E402

from tests.auth_helpers import ADMIN_HEADERS as ADMIN, make_user  # noqa: E402

PUBLIC = "93.184.216.34"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    monkeypatch.setattr(settings, "use_mock_engine", True)
    monkeypatch.setattr(settings, "scan_logs_dir", str(tmp_path / "scan_logs"))
    monkeypatch.setattr(settings, "llm_allowed_hosts", "")
    monkeypatch.setattr(settings, "llm_allow_loopback", True)
    init_db(f"sqlite:///{(tmp_path / 'policy.db').as_posix()}")
    return TestClient(app)


def _create(client, name, **llm):
    return client.post(
        "/projects", headers=ADMIN,
        json={"name": name, "default_git_url": "https://github.com/org/repo.git", **llm},
    )


def _compat(url):
    return {"llm_provider": "openai_compat", "llm_model": "qwen", "llm_base_url": url}


@pytest.mark.integration
def test_a_project_cannot_be_pointed_at_a_disallowed_endpoint(client):
    for url in (f"http://{PUBLIC}/v1", "https://169.254.169.254/v1", "http://metadata.google.internal/v1",
                "https://user:pw@93.184.216.34/v1", "https://10.1.2.3/v1", "ftp://93.184.216.34/v1"):
        resp = _create(client, "bad", **_compat(url))
        assert resp.status_code == 422, url
        assert "endpoint not allowed" in resp.json()["detail"]
    assert _create(client, "good", **_compat(f"https://{PUBLIC}/v1")).status_code == 201
    assert _create(client, "local", **_compat("http://localhost:8000/v1")).status_code == 201
    assert _create(client, "default").status_code == 201  # bedrock needs no endpoint


@pytest.mark.integration
def test_an_administrator_can_approve_a_private_host(client):
    assert _create(client, "internal", **_compat("http://10.1.2.3:8000/v1")).status_code == 422
    put = client.put("/settings/llm-policy", headers=ADMIN, json={"allowed_hosts": ["10.1.2.3:8000"]})
    assert put.status_code == 200 and put.json()["allowed_hosts"] == ["10.1.2.3:8000"]
    assert _create(client, "internal", **_compat("http://10.1.2.3:8000/v1")).status_code == 201
    assert _create(client, "other-port", **_compat("http://10.1.2.3:9000/v1")).status_code == 422


@pytest.mark.integration
def test_only_an_approver_can_change_the_policy_but_anyone_can_read_it(client):
    _uid, user = make_user("plain@test.local", "user")
    assert client.get("/settings/llm-policy", headers=user).status_code == 200
    resp = client.put("/settings/llm-policy", headers=user, json={"allowed_hosts": ["x.example.com"]})
    assert resp.status_code == 403
    assert client.get("/settings/llm-policy", headers=ADMIN).json()["allowed_hosts"] == []


@pytest.mark.integration
@pytest.mark.parametrize("bad", ["http://x.example.com", "a b", "x/y", "-" * 300])
def test_the_policy_rejects_entries_that_are_not_hosts(client, bad):
    resp = client.put("/settings/llm-policy", headers=ADMIN, json={"allowed_hosts": [bad]})
    assert resp.status_code == 422


@pytest.mark.integration
def test_a_model_allow_list_restricts_projects_and_scans(client):
    project_id = _create(client, "p").json()["id"]
    client.put("/settings/llm-policy", headers=ADMIN, json={"allowed_models": ["approved-model"]})
    assert _create(client, "q", llm_model="other-model").status_code == 422
    assert _create(client, "r", llm_provider="ollama", llm_model="approved-model").status_code == 201
    scan = client.post("/scans", headers=ADMIN, json={"project_id": project_id, "commit_sha": "a1"})
    assert scan.status_code == 422 and "approved model list" in scan.json()["detail"]
    override = client.post("/scans", headers=ADMIN, json={
        "project_id": project_id, "commit_sha": "a2", "llm_provider": "ollama", "llm_model": "approved-model",
    })
    assert override.status_code in (200, 201, 202)


@pytest.mark.integration
def test_patching_an_llm_field_is_checked_but_an_unrelated_edit_is_not(client):
    project_id = _create(client, "p").json()["id"]
    bad = client.patch(f"/projects/{project_id}", headers=ADMIN, json={"llm_provider": "openai_compat",
                       "llm_base_url": "https://169.254.169.254/v1"})
    assert bad.status_code == 422
    with db_module.SessionLocal() as db:  # a project saved before the policy existed
        project = db.get(Project, project_id)
        project.llm_provider, project.llm_base_url = "openai_compat", "http://10.9.9.9/v1"
        db.commit()
    assert client.patch(f"/projects/{project_id}", headers=ADMIN, json={"name": "renamed"}).status_code == 200


@pytest.mark.integration
def test_a_scan_override_cannot_reach_a_disallowed_endpoint_and_an_unknown_provider_is_a_422(client):
    project_id = _create(client, "p").json()["id"]
    resp = client.post("/scans", headers=ADMIN, json={"project_id": project_id, "commit_sha": "b1",
                       "llm_provider": "not-a-provider"})
    assert resp.status_code == 422
    resp = client.post("/scans", headers=ADMIN, json={"project_id": project_id, "commit_sha": "b2",
                       "llm_provider": "ollama", "llm_model": "m"})
    assert resp.status_code in (200, 201, 202)


@pytest.mark.integration
def test_a_legacy_row_is_stopped_when_the_scan_starts(client):
    from types import SimpleNamespace

    project = SimpleNamespace(llm_base_url="http://169.254.169.254/v1", limitations_config=None)
    scan = SimpleNamespace(
        id="s1", llm_provider="openai_compat", llm_model="m", llm_base_url=project.llm_base_url,
        fallback_llm_provider=None, fallback_llm_model=None,
    )
    with pytest.raises(llm_policy.LlmPolicyError, match="endpoint not allowed"):
        agent_bridge.llm_usage_options(project, scan)
    ok_scan = SimpleNamespace(id="s2", llm_provider="bedrock", llm_model="m", llm_base_url=None,
                              fallback_llm_provider=None, fallback_llm_model=None)
    options = agent_bridge.llm_usage_options(project, ok_scan)
    assert options["endpoint_policy"] == {"allowed_hosts": [], "allow_loopback": True}


@pytest.mark.integration
def test_the_server_env_hosts_are_part_of_the_policy_and_the_loopback_switch_is_honoured(client, monkeypatch):
    monkeypatch.setattr(settings, "llm_allowed_hosts", "vllm.corp.internal, 10.1.2.3")
    assert llm_policy.load_policy()["allowed_hosts"] == ["10.1.2.3", "vllm.corp.internal"]
    monkeypatch.setattr(settings, "llm_allow_loopback", False)
    assert _create(client, "loop", **_compat("http://localhost:8000/v1")).status_code == 422


@pytest.mark.integration
def test_the_scan_records_where_code_went_and_under_which_policy(client):
    scan = Scan(project_id="p", git_url="u", llm_provider="openai_compat", llm_model="m",
                llm_base_url=f"https://{PUBLIC}:8443/v1/secret-path?token=abc")
    versions = scan_versions.static_versions(scan, mock=False)
    assert versions["llm_endpoint_host"] == PUBLIC  # the host only
    assert len(versions["llm_policy_sha256"]) == 64
    before = versions["llm_policy_sha256"]
    client.put("/settings/llm-policy", headers=ADMIN, json={"allowed_hosts": ["x.example.com"]})
    assert scan_versions.static_versions(scan, mock=False)["llm_policy_sha256"] != before


def test_bedrock_claude_5_request_omits_temperature(monkeypatch):
    """Claude 5 models on Bedrock reject `temperature`; older ones still get it."""
    import json as _json
    import llm_client as llm

    assert not llm.bedrock_accepts_temperature("us.anthropic.claude-sonnet-5-5")
    assert not llm.bedrock_accepts_temperature("global.anthropic.claude-sonnet-5")
    assert llm.bedrock_accepts_temperature("us.anthropic.claude-sonnet-4-5-20250929-v1:0")
    assert llm.bedrock_accepts_temperature("us.anthropic.claude-haiku-4-5-20251001-v1:0")

    sent: dict = {}

    class _Body:
        def read(self):
            return _json.dumps({"content": [{"text": "ok"}], "usage": {"input_tokens": 1, "output_tokens": 1}})

    class _Client:
        def invoke_model(self, **kw):
            sent.update(_json.loads(kw["body"]))
            return {"body": _Body()}

    monkeypatch.setattr(llm, "_bedrock", _Client())
    for model, expect in (("us.anthropic.claude-sonnet-5-5", False), ("us.anthropic.claude-sonnet-4-5-20250929-v1:0", True)):
        sent.clear()
        llm._call_bedrock("s", "u", model, 16, 0.0, 1, usage=None, step="t")
        assert ("temperature" in sent) is expect


def test_bedrock_claude_5_json_mode_has_no_prefill(monkeypatch):
    """Claude 5 rejects assistant prefill: JSON mode asks in the prompt, unwraps fences,
    and never prepends a `{`. Older models keep the prefill."""
    import json as _json
    import llm_client as llm

    sent: dict = {}
    reply = {"text": '```json\n{"a": 1}\n```'}

    class _Body:
        def read(self):
            return _json.dumps({"content": [{"text": reply["text"]}], "usage": {"input_tokens": 1, "output_tokens": 1}})

    class _Client:
        def invoke_model(self, **kw):
            sent.clear()
            sent.update(_json.loads(kw["body"]))
            return {"body": _Body()}

    monkeypatch.setattr(llm, "_bedrock", _Client())
    out = llm._call_bedrock("s", "u", "us.anthropic.claude-sonnet-5-5", 16, 0.0, 1, usage=None, step="t", json_mode=True)
    assert out == '{"a": 1}'
    assert [m["role"] for m in sent["messages"]] == ["user"]
    assert "JSON object only" in sent["messages"][0]["content"]

    reply["text"] = '"a": 1}'
    out = llm._call_bedrock("s", "u", "us.anthropic.claude-haiku-4-5-20251001-v1:0", 16, 0.0, 1, usage=None, step="t", json_mode=True)
    assert out == '{"a": 1}'
    assert [m["role"] for m in sent["messages"]] == ["user", "assistant"]
