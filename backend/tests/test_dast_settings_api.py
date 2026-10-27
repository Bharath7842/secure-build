"""EPIC-15 backend: editable global settings, model routing (with a test-connection call), the
read-only provider status, the rule-settings view with value sources, and custom-rule validation.
Edits apply to new scans only; no secret is ever returned."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
import yaml
from fastapi.testclient import TestClient

from app import db as app_db
from app.config import settings
from app.main import app
from app.models import Scan
from app.services import dast_settings

pytestmark = pytest.mark.integration

from tests.auth_helpers import ADMIN_HEADERS  # noqa: E402

HDR = ADMIN_HEADERS
OAST = "https://oast-secret-host.example/abc123"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    monkeypatch.setattr(settings, "use_mock_engine", True)
    monkeypatch.setattr(settings, "scan_logs_dir", str(tmp_path / "scan_logs"))
    monkeypatch.setattr(settings, "dast_oast_callback_url", None)
    app_db.init_db(f"sqlite:///{(tmp_path / 's.db').as_posix()}")
    return TestClient(app)


@pytest.fixture()
def project_id(client):
    return client.post("/projects", json={"name": "settings", "default_git_url": ""}, headers=HDR).json()["id"]


def scan(client, project_id, **dast):
    body = {"project_id": project_id, "scan_type": "dast", "dast": {"target_url": "http://localhost:3000", "authorized": True, **dast}}
    response = client.post("/scans", json=body, headers=HDR)
    assert response.status_code == 202, response.text
    return response.json()["scan_id"]


def snapshot(scan_id):
    with app_db.SessionLocal() as db:
        return dict(db.get(Scan, scan_id).metadata_json)


def patch(client, **body):
    return client.patch("/dast/settings", json=body, headers=HDR)


# ---- scan defaults (DAST-15-050) ---------------------------------------------------------------------------


def test_settings_read_the_environment_until_edited_and_say_they_apply_to_new_scans(client):
    body = client.get("/dast/settings", headers=HDR).json()
    assert body["max_pages"] == settings.dast_max_pages and body["safe_mode_default"] is True and body["overridden"] == []
    assert body["oast_configured"] is False and body["applies_to"] == "new scans only"
    assert [r["task"] for r in body["model_routing"]] == ["fingerprint", "crawl_plan", "login_selectors", "normalize_endpoints", "plan", "construct", "rule", "narrate"]
    assert body["limits"]["max_pages"] == {"min": 1, "max": 1000, "label": "Maximum pages crawled"}


def test_an_edit_changes_new_scans_only(client, project_id):
    before = scan(client, project_id)
    assert patch(client, max_pages=77, max_depth=2, rate_limit_per_sec=1.5, same_domain_mode="root-domain").status_code == 200
    after = scan(client, project_id)
    eff_before, eff_after = snapshot(before)["dast_effective"], snapshot(after)["dast_effective"]
    assert eff_before["max_pages"] == settings.dast_max_pages and eff_after["max_pages"] == 77
    assert eff_after["max_depth"] == 2 and eff_after["rate_limit_per_sec"] == 1.5 and eff_after["same_domain_mode"] == "root-domain"
    assert snapshot(before)["dast_effective"] == eff_before  # a past scan keeps what it ran with
    body = client.get("/dast/settings", headers=HDR).json()
    assert body["max_pages"] == 77 and set(body["overridden"]) == {"max_pages", "max_depth", "rate_limit_per_sec", "same_domain_mode"}


@pytest.mark.parametrize(
    "field, value, message",
    [
        ("max_pages", 0, "at least 1"), ("max_pages", 5000, "at most 1000"), ("max_pages", 2.5, "whole number"), ("max_pages", "many", "must be a number"),
        ("max_depth", 11, "at most 10"), ("rate_limit_per_sec", 0, "at least 0.1"), ("rate_limit_per_sec", 1000, "at most 100"),
        ("max_runtime_minutes", 0.1, "at least 0.5"), ("same_domain_mode", "any", "must be one of"), ("oast_callback_url", "ftp://x", "http://"),
        ("max_pages", True, "must be a number"),
    ],
)
def test_out_of_range_values_are_rejected_with_a_message_per_field(client, field, value, message):
    r = patch(client, **{field: value})
    assert r.status_code == 422, r.text
    errors = r.json()["detail"]["errors"] if "errors" in r.json().get("detail", {}) else r.json()["detail"]
    text = json.dumps(errors)
    assert field in text and (message in text or "valid" in text or "type" in text), text
    assert client.get("/dast/settings", headers=HDR).json()["overridden"] == []  # nothing was stored


def test_unknown_fields_are_rejected_and_every_invalid_field_is_reported_together(client):
    assert client.patch("/dast/settings", json={"made_up": 1}, headers=HDR).status_code == 422
    r = patch(client, max_pages=0, max_depth=99)
    assert {e["field"] for e in r.json()["detail"]["errors"]} == {"max_pages", "max_depth"}


def test_the_safe_mode_default_cannot_be_turned_off_without_confirmation(client, project_id):
    refused = patch(client, safe_mode_default=False)
    assert refused.status_code == 422 and "confirmation" in json.dumps(refused.json())
    assert client.get("/dast/settings", headers=HDR).json()["safe_mode_default"] is True
    assert patch(client, safe_mode_default=False, confirm_unsafe=True).status_code == 200
    assert client.get("/dast/settings", headers=HDR).json()["safe_mode_default"] is False
    # an unspecified method policy follows the default, but only for a disposable target
    plain = scan(client, project_id)
    assert snapshot(plain)["dast_effective"]["method_policy"] == "safe"
    disposable = scan(client, project_id, target_disposable=True)
    assert snapshot(disposable)["dast_effective"]["method_policy"] == "opt_in_mutating"
    explicit = scan(client, project_id, target_disposable=True, method_policy="safe")
    assert snapshot(explicit)["dast_effective"]["method_policy"] == "safe"  # an explicit choice always wins
    assert patch(client, safe_mode_default=True).status_code == 200  # turning it back on needs nothing


def test_marker_posts_need_confirmation_and_a_disposable_target(client, project_id):
    refused = patch(client, browser_marker_posts=True)
    assert refused.status_code == 422 and "confirmation" in json.dumps(refused.json())
    assert client.get("/dast/settings", headers=HDR).json()["browser_marker_posts"] is False
    assert patch(client, browser_marker_posts=True, confirm_unsafe=True).status_code == 200
    blocked = client.post(
        "/scans",
        json={"project_id": project_id, "scan_type": "dast", "dast": {"target_url": "http://localhost:3000", "authorized": True, "browser_marker_posts": True}},
        headers=HDR,
    )
    assert blocked.status_code == 422 and "disposable" in blocked.text
    created = scan(client, project_id, target_disposable=True, browser_marker_posts=True)
    effective = snapshot(created)["dast_effective"]
    assert effective["browser_marker_posts"] is True
    stored = next(c for c in snapshot(created)["dast_rule_set"]["checks"] if c["id"] == "dast-xss-stored")
    assert stored["enabled"] is True
    assert patch(client, browser_marker_posts=False).status_code == 200


def test_the_oast_address_is_write_only_and_changes_what_new_scans_can_do(client, project_id):
    ssrf_before = [e for e in snapshot(scan(client, project_id))["dast_skipped_degraded"] if e["check_id"] == "dast-ssrf"]
    assert ssrf_before and ssrf_before[0]["effective_mode"] == "assist-only"
    r = patch(client, oast_callback_url=OAST)
    assert r.status_code == 200 and r.json()["oast_configured"] is True and "oast-secret-host" not in r.text
    assert "oast-secret-host" not in client.get("/dast/settings", headers=HDR).text
    after = scan(client, project_id)
    meta = snapshot(after)
    assert meta["dast_effective"]["oast_configured"] is True and not [e for e in meta["dast_skipped_degraded"] if e["check_id"] == "dast-ssrf"]
    assert "oast-secret-host" not in json.dumps(meta)  # never copied into a scan
    assert dast_settings.current_oast_url() == OAST
    cleared = patch(client, oast_callback_url="")
    assert cleared.json()["oast_configured"] is False and dast_settings.current_oast_url() is None


def test_settings_need_the_bearer_token(client):
    assert client.get("/dast/settings").status_code in (401, 403)
    assert client.patch("/dast/settings", json={"max_pages": 5}).status_code in (401, 403)
    assert client.put("/dast/model-routing", json=[]).status_code in (401, 403)
    assert client.post("/dast/model-routing/test", json={"task": "rule", "provider": "ollama"}).status_code in (401, 403)


# ---- model routing (DAST-15-010) ---------------------------------------------------------------------------


def test_routing_lists_all_tasks_and_a_change_reaches_the_next_scans_snapshot_only(client, project_id):
    routes = client.get("/dast/model-routing", headers=HDR).json()
    assert {r["task"] for r in routes} == {"fingerprint", "crawl_plan", "login_selectors", "normalize_endpoints", "plan", "construct", "rule", "narrate"} and all(r["provider"] == "ollama" for r in routes)
    before = scan(client, project_id)
    put = client.put("/dast/model-routing", json=[{"task": "rule", "provider": "anthropic", "model": "claude-x"}], headers=HDR)
    assert put.status_code == 200
    rule = next(r for r in put.json() if r["task"] == "rule")
    assert (rule["provider"], rule["model"], rule["overridden"]) == ("anthropic", "claude-x", True)
    after = scan(client, project_id, model_routing={"construct": {"provider": "ollama", "model": "gpt-oss:20b"}})
    assert snapshot(before)["dast_effective"]["model_routing"]["rule"][0] == "ollama"
    assert snapshot(after)["dast_effective"]["model_routing"]["rule"] == ["anthropic", "claude-x"]


@pytest.mark.parametrize(
    "route, field",
    [
        ({"task": "nope", "provider": "ollama", "model": "m"}, "task"),
        ({"task": "rule", "provider": "skynet", "model": "m"}, "provider"),
        ({"task": "rule", "provider": "openai", "model": ""}, "model"),
        ({"task": "rule", "provider": "ollama", "model": "bad\nname"}, "model"),
    ],
)
def test_an_invalid_route_is_rejected_and_nothing_is_stored(client, route, field):
    r = client.put("/dast/model-routing", json=[route], headers=HDR)
    assert r.status_code == 422 and field in json.dumps(r.json())
    assert not any(row["overridden"] for row in client.get("/dast/model-routing", headers=HDR).json())


def test_test_connection_reports_success(client, monkeypatch):
    class Gateway:
        def check_configuration(self):
            return []

        def complete(self, task, system, prompt, schema, **kw):
            return SimpleNamespace(fallback_used=False, data={"ok": True})

    monkeypatch.setattr("app.services.model_gateway.build_gateway", lambda routing, **kw: Gateway())
    r = client.post("/dast/model-routing/test", json={"task": "rule", "provider": "ollama", "model": "m"}, headers=HDR).json()
    assert r["ok"] is True and r["task"] == "rule" and r["error"] is None and r["latency_ms"] is not None


def test_test_connection_reports_the_failure_reason_without_leaking_a_key(client, monkeypatch):
    key = "sk-ant-api03-supersecretkeyvalue1234567890"

    class Gateway:
        def check_configuration(self):
            return []

        def complete(self, *a, **kw):
            raise RuntimeError(f"401 invalid x-api-key {key}")

    monkeypatch.setattr("app.services.model_gateway.build_gateway", lambda routing, **kw: Gateway())
    r = client.post("/dast/model-routing/test", json={"task": "rule", "provider": "anthropic", "model": "claude-x"}, headers=HDR)
    body = r.json()
    assert body["ok"] is False and "401" in body["error"] and key not in r.text
    missing = client.post("/dast/model-routing/test", json={"task": "rule", "provider": "openai", "model": "gpt-x"}, headers=HDR).json()
    assert missing["ok"] is False and missing["error"]  # no key configured: the reason is reported, not raised
    assert client.post("/dast/model-routing/test", json={"task": "bogus", "provider": "ollama"}, headers=HDR).json()["ok"] is False


# ---- credentials status (DAST-15-020) ----------------------------------------------------------------------


def test_provider_status_is_read_only_and_never_returns_a_value(client, monkeypatch):
    secret = "sk-openai-supersecret-0123456789abcdef"
    from pydantic import SecretStr

    monkeypatch.setattr(settings, "openai_api_key", SecretStr(secret))
    monkeypatch.setattr(settings, "anthropic_api_key", None)
    r = client.get("/dast/providers", headers=HDR)
    by = {p["provider"]: p for p in r.json()["providers"]}
    assert by["openai"]["configured"] is True and by["anthropic"]["configured"] is False and by["ollama"]["configured"] is True
    assert r.json()["writable"] is False and r.json()["storage"] == "environment"
    assert r.json()["default_models"]["bedrock"].startswith("us.anthropic.claude-haiku")
    assert r.json()["default_models"]["ollama"]
    assert secret not in r.text and secret not in client.get("/dast/settings", headers=HDR).text
    for method in (client.put, client.post, client.patch):
        assert method("/dast/providers", json={"openai": "x"}, headers=HDR).status_code in (404, 405)  # no write path exists


# ---- rule settings (DAST-15-030) ---------------------------------------------------------------------------


def row(view, check_id):
    return next(c for c in view["checks"] if c["check_id"] == check_id)


def test_rule_settings_show_effective_values_sources_and_dependencies(client, project_id):
    view = client.get("/dast/rule-settings", headers=HDR).json()
    assert view["level"] == "global" and view["applies_to"] == "new scans only"
    api4 = row(view, "dast-resource-consumption")
    assert api4["enabled"] == {"value": False, "source": "default"} and api4["off_by_default"] and api4["load_generating"]
    bola = row(view, "dast-bola")
    assert bola["requires"] == ["second_identity"] and bola["severity"] == {"value": "HIGH", "source": "default"}
    assert {p["id"] for p in view["packs"]} >= {"owasp-api-top10-2023", "passive-only"}
    assert all(p["source"] == "default" for p in view["packs"])

    assert client.patch("/dast/rules", json={"checks": {"dast-bola": {"severity": "CRITICAL"}}, "packs": {"wstg-full": True}}, headers=HDR).status_code == 200
    view = client.get("/dast/rule-settings", headers=HDR).json()
    assert row(view, "dast-bola")["severity"] == {"value": "CRITICAL", "source": "global"} and next(p for p in view["packs"] if p["id"] == "wstg-full") == {**next(p for p in view["packs"] if p["id"] == "wstg-full"), "enabled": True, "source": "global"}

    assert client.patch(f"/projects/{project_id}/dast-rules", json={"checks": {"dast-bola": {"mode": "assist-only"}, "dast-xss": {"enabled": False}}}, headers=HDR).status_code == 200
    project_view = client.get("/dast/rule-settings", params={"project_id": project_id}, headers=HDR).json()
    assert project_view["level"] == "project"
    assert row(project_view, "dast-bola")["mode"] == {"value": "assist-only", "source": "project"} and row(project_view, "dast-bola")["severity"]["source"] == "global"
    assert row(project_view, "dast-xss")["enabled"] == {"value": False, "source": "project"}
    assert row(view, "dast-xss")["enabled"]["source"] == "default"  # the global level is untouched by the project override
    assert client.get("/dast/rule-settings", params={"project_id": "missing"}, headers=HDR).status_code == 404


def test_a_rule_change_shows_in_the_next_scans_snapshot_and_not_a_past_ones(client, project_id):
    before = scan(client, project_id)
    client.patch("/dast/rules", json={"checks": {"dast-sqli": {"severity": "LOW"}}}, headers=HDR)
    after = scan(client, project_id)
    sev = lambda s: next(c for c in snapshot(s)["dast_rule_set"]["checks"] if c["id"] == "dast-sqli")["severity"]  # noqa: E731
    assert sev(before) == "HIGH" and sev(after) == "LOW"


def test_the_effective_preview_takes_a_pack_selection_for_the_check_count(client):
    count = lambda **p: sum(1 for c in client.get("/dast/rules/effective", params=p, headers=HDR).json()["rule_set"]["checks"] if c["enabled"])  # noqa: E731
    default = count()
    assert count(packs="passive-only") < default and count(packs="passive-only") > 0
    assert count(packs="owasp-web-top10,passive-only") >= count(packs="owasp-web-top10")
    assert client.get("/dast/rules/effective", params={"packs": "nope"}, headers=HDR).status_code == 422


# ---- custom rule validation (DAST-15-040) ------------------------------------------------------------------

RULE = {
    "id": "dast-custom-reflect", "title": "Custom reflection", "owasp": ["A03:2021"], "cwe": ["CWE-79"],
    "location": "query", "signal": ["input_reflected_unescaped"], "severity": "MEDIUM", "mode": "automated",
}


def validate(client, **over):
    return client.post("/dast/custom-rules/validate", json={"yaml": yaml.safe_dump({**RULE, **over})}, headers=HDR).json()


def test_a_valid_rule_validates_without_being_saved(client):
    body = validate(client)
    assert body == {"valid": True, "errors": [], "notes": []}
    assert client.get("/dast/custom-rules", headers=HDR).json()["rules"] == []


@pytest.mark.parametrize(
    "over, field, expected",
    [
        ({"signal": ["made_up_signal"]}, "signal", "unknown detector signal"),
        ({"payload": "' OR 1=1"}, "payload", "fixed payload"),
        ({"owasp": [], "cwe": []}, "standards", "standard tag"),
        ({"mode": "whenever"}, "mode", "mode"),
        ({"id": "dast-sqli"}, "id", "already used"),
    ],
)
def test_each_invalid_case_reports_its_field_and_reason(client, over, field, expected):
    body = validate(client, **over)
    assert body["valid"] is False and any(expected in e["message"] and e["field"] == field for e in body["errors"]), body


def test_bad_yaml_and_a_rule_that_can_only_be_assist_only_say_so(client):
    broken = client.post("/dast/custom-rules/validate", json={"yaml": "id: [unclosed"}, headers=HDR).json()
    assert broken["valid"] is False and broken["errors"][0]["field"] == "rule" and "YAML" in broken["errors"][0]["message"]
    review = validate(client, id="dast-custom-review", signal=[])
    assert review["valid"] is True and any("assist-only" in n for n in review["notes"])


def test_claude_cli_is_a_known_routing_provider(client):
    """The local claude CLI can be routed per task; an empty model means its default."""
    from app.config import settings

    resp = client.put("/dast/model-routing", json=[{"task": "narrate", "provider": "claude_cli", "model": ""}], headers=HDR)
    assert resp.status_code == 200, resp.text
    row = next(r for r in resp.json() if r["task"] == "narrate")
    assert (row["provider"], row["model"]) == ("claude_cli", settings.dast_claude_cli_model)
    providers = client.get("/dast/providers", headers=HDR).json()
    assert any(p["provider"] == "claude_cli" for p in providers["providers"])
    assert providers["default_models"]["claude_cli"] == settings.dast_claude_cli_model


def test_agent_defaults_are_snapshotted_and_scan_overrides_win(client, project_id):
    before = scan(client, project_id)
    response = patch(client, agent_mode=True, max_agent_turns=17, max_turns_per_hypothesis=3)
    assert response.status_code == 200, response.text
    assert response.json()["agent_mode"] is True
    after = scan(client, project_id)
    overridden = scan(client, project_id, agent_mode=False, max_agent_turns=5, max_turns_per_hypothesis=2)
    assert snapshot(before)["dast_effective"]["agent_mode"] is False
    assert snapshot(after)["dast_effective"]["max_agent_turns"] == 17
    assert snapshot(after)["dast_effective"]["max_turns_per_hypothesis"] == 3
    eff = snapshot(overridden)["dast_effective"]
    assert eff["agent_mode"] is False and eff["max_agent_turns"] == 5 and eff["max_turns_per_hypothesis"] == 2
    assert snapshot(overridden)["dast_input"]["max_agent_turns"] == 5


@pytest.mark.parametrize("field,value", [("max_agent_turns", 0), ("max_agent_turns", 1001), ("max_turns_per_hypothesis", 21), ("max_turns_per_hypothesis", 1.5)])
def test_agent_budget_settings_reject_invalid_values(client, field, value):
    assert patch(client, **{field: value}).status_code == 422
