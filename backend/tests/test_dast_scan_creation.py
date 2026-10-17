"""DAST-05-010 / -020 and DAST-06-010 end to end: the creation contract, the frozen effective
settings, and that no credential survives anywhere (offline, mock engine)."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app import db as app_db
from app.config import settings
from app.dast.domain.presets import DEFAULT_DEEP, DEFAULT_LIGHT
from app.main import app
from app.models import DastEvidence, DastRequestAudit, Finding, Scan
from app.services import scan_log, scan_runner

pytestmark = pytest.mark.integration

from tests.auth_helpers import ADMIN_HEADERS  # noqa: E402

HDR = ADMIN_HEADERS
PASSWORD = "Pw-s3cret-Value-1"
TOKEN = "tok_live_abcdef0123456789"
COOKIE = "sessioncookie-9f8e7d6c5b4a"
URL = "http://localhost:3000"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    monkeypatch.setattr(settings, "use_mock_engine", True)
    monkeypatch.setattr(settings, "scan_logs_dir", str(tmp_path / "scan_logs"))
    app_db.init_db(f"sqlite:///{(tmp_path / 'c.db').as_posix()}")
    return TestClient(app)


@pytest.fixture()
def project_id(client):
    return client.post("/projects", json={"name": "creation", "default_git_url": ""}, headers=HDR).json()["id"]


def post(client, project_id, **dast):
    body = {"target_url": URL, "authorized": True, **dast}
    return client.post("/scans", json={"project_id": project_id, "scan_type": "dast", "dast": body}, headers=HDR)


def stored(scan_id):
    with app_db.SessionLocal() as db:
        return db.get(Scan, scan_id).metadata_json


STORAGE_STATE = {"cookies": [{"name": "session", "value": COOKIE, "domain": "localhost", "path": "/"}], "origins": []}

IDENTITIES = [
    {"label": "Admin A", "role": "Admin", "auth_method": "form", "login_url": f"{URL}/login", "username": "admin", "password": PASSWORD},
    {"label": "Service", "role": "Custom", "custom_role": "Auditor", "auth_method": "token", "token": TOKEN},
    {"label": "Saved", "role": "Viewer", "auth_method": "preauth", "storage_state": STORAGE_STATE},
]


# ---- DAST-05-010 ------------------------------------------------------------------------------


def test_a_full_multi_identity_request_is_accepted_and_the_scan_gets_a_version(client, project_id):
    r = post(client, project_id, identities=IDENTITIES, intensity="deep", method_policy="opt_in_mutating", target_disposable=True,
             rate_limit_per_sec=2, rule_packs=["owasp-api-top10-2023"], rule_overrides={"dast-xss": {"severity": "LOW"}},
             model_routing={"narrate": {"provider": "ollama", "model": "llama3"}}, max_pages=7)
    assert r.status_code == 202, r.text
    scan_id = r.json()["scan_id"]
    meta = stored(scan_id)
    assert [i["label"] for i in meta["dast_input"]["identities"]] == ["Admin A", "Service", "Saved", "anonymous"]
    assert {i["role"] for i in meta["dast_input"]["identities"]} == {"admin", "custom", "viewer", "anonymous"}
    assert next(i for i in meta["dast_input"]["identities"] if i["label"] == "Service")["role_label"] == "Auditor"
    assert [i["has_secret"] for i in meta["dast_input"]["identities"]] == [True, True, True, False]
    second = post(client, project_id, identities=IDENTITIES[:1])
    with app_db.SessionLocal() as db:
        assert [s.version for s in db.query(Scan).order_by(Scan.version)] == [1, 2]
    assert second.status_code == 202


def test_missing_authorization_is_rejected_with_a_clear_message(client, project_id):
    r = post(client, project_id, authorized=False, identities=IDENTITIES[:1])
    assert r.status_code == 400 and "authorized" in r.json()["detail"]


def test_the_original_request_shape_still_works_as_one_form_identity(client, project_id):
    r = post(client, project_id, login_url=f"{URL}/login", username="admin", password=PASSWORD, max_depth=2, max_pages=5)
    assert r.status_code == 202
    meta = stored(r.json()["scan_id"])
    identities = meta["dast_input"]["identities"]
    assert [(i["label"], i["auth_method"], i["has_secret"]) for i in identities] == [("default", "form", True), ("anonymous", "none", False)]
    assert meta["dast_input"]["has_password"] is True and meta["dast_input"]["username"] == "admin"
    assert meta["dast_effective"]["max_depth"] == 2 and meta["dast_effective"]["max_pages"] == 5
    assert client.get(f"/scans/{r.json()['scan_id']}/status", headers=HDR).json()["status"] == "success"


def test_no_credential_appears_in_the_stored_scan_json(client, project_id):
    r = post(client, project_id, identities=IDENTITIES)
    scan_id = r.json()["scan_id"]
    blob = json.dumps(stored(scan_id))
    for secret in (PASSWORD, TOKEN, COOKIE):
        assert secret not in blob
    with app_db.SessionLocal() as db:
        raw = db.execute(text("SELECT metadata FROM scans WHERE id = :i"), {"i": scan_id}).scalar()
    assert not any(secret in str(raw) for secret in (PASSWORD, TOKEN, COOKIE))


def test_no_credential_reaches_any_endpoint_output(client, project_id):
    scan_id = post(client, project_id, identities=IDENTITIES).json()["scan_id"]
    for path in ("status", "results", "logs", "findings", "narration", "requests"):
        text_ = client.get(f"/scans/{scan_id}/{path}", headers=HDR).text
        assert not any(secret in text_ for secret in (PASSWORD, TOKEN, COOKIE)), path
    for path in ("export.xlsx", "export.pdf"):
        r = client.get(f"/scans/{scan_id}/{path}", headers=HDR)
        assert r.status_code == 200 and not any(secret.encode() in r.content for secret in (PASSWORD, TOKEN, COOKIE)), path
    assert not any(secret in client.get("/scans", headers=HDR).text for secret in (PASSWORD, TOKEN, COOKIE))


@pytest.mark.parametrize(
    "identities, expected",
    [
        ([{"label": "a", "role": "User", "auth_method": "form", "login_url": URL, "username": "u", "password": "p"}] * 2, "unique"),
        ([{"label": "a", "role": "Nobody", "auth_method": "token", "token": "x"}], "role"),
        ([{"label": "a", "role": "Custom", "auth_method": "token", "token": "x"}], "role name"),
        ([{"label": "a", "role": "Anonymous", "auth_method": "token", "token": "x"}], "Anonymous"),
        ([{"label": "a", "role": "User", "auth_method": "form"}], "form login needs"),
        ([{"label": "a", "role": "User", "auth_method": "token"}], "needs a token"),
        ([{"label": "a", "role": "User", "auth_method": "preauth"}], "storage_state"),
        ([{"label": "a", "role": "User", "auth_method": "preauth", "storage_state": {"cookies": "no"}}], "lists"),
        ([{"label": "", "role": "User", "auth_method": "token", "token": "x"}], "label"),
    ],
)
def test_invalid_identities_are_rejected_before_a_scan_exists(client, project_id, identities, expected):
    r = post(client, project_id, identities=identities)
    assert r.status_code in (400, 422) and expected in r.text
    with app_db.SessionLocal() as db:
        assert db.query(Scan).count() == 0


def test_mixing_the_legacy_credential_with_identities_is_rejected(client, project_id):
    r = post(client, project_id, identities=IDENTITIES[:1], login_url=f"{URL}/login", username="a", password="b")
    assert r.status_code == 422 and "either" in r.text


def test_mutating_methods_need_a_disposable_target(client, project_id):
    r = post(client, project_id, method_policy="opt_in_mutating")
    assert r.status_code == 422 and "disposable" in r.json()["detail"]
    assert post(client, project_id, method_policy="opt_in_mutating", target_disposable=True).status_code == 202


@pytest.mark.parametrize(
    "extra, expected",
    [
        ({"rule_packs": ["nope"]}, "unknown rule pack"),
        ({"rule_overrides": {"dast-nope": {"enabled": True}}}, "unknown check"),
        ({"intensity": "extreme"}, "intensity"),
        ({"model_routing": {"nope": {"provider": "ollama"}}}, "unknown model task"),
        ({"model_routing": {"rule": {"provider": "skynet"}}}, "provider"),
        ({"model_routing": {"rule": {"provider": "openai"}}}, "explicit model"),
        ({"model_routing": {"rule": {"provider": "anthropic", "model": "claude-x"}}}, "anthropic_api_key"),
    ],
)
def test_bad_configuration_is_rejected_with_a_specific_reason(client, project_id, extra, expected):
    r = post(client, project_id, **extra)
    assert r.status_code in (400, 422) and expected in r.text
    with app_db.SessionLocal() as db:
        assert db.query(Scan).count() == 0


def test_a_hosted_model_is_accepted_when_its_key_is_configured(client, project_id, monkeypatch):
    from pydantic import SecretStr

    monkeypatch.setattr(settings, "anthropic_api_key", SecretStr("sk-ant-test-0123456789"))
    r = post(client, project_id, model_routing={"rule": {"provider": "anthropic", "model": "claude-x"}})
    assert r.status_code == 202
    routing = stored(r.json()["scan_id"])["dast_effective"]["model_routing"]
    assert routing["rule"] == ["anthropic", "claude-x"] and routing["narrate"][0] == "ollama"
    assert "sk-ant" not in json.dumps(stored(r.json()["scan_id"]))
    with app_db.SessionLocal() as db:
        scan = db.get(Scan, r.json()["scan_id"])
        assert scan.llm_provider == "ollama"  # five of six tasks still use the default local model


def test_dast_scan_row_records_bedrock_when_every_task_uses_it(client, project_id):
    routing = {task: {"provider": "bedrock", "model": "us.anthropic.claude-haiku-4-5-20251001-v1:0"} for task in ("fingerprint", "crawl_plan", "login_selectors", "construct", "rule", "narrate")}
    r = post(client, project_id, model_routing=routing)
    assert r.status_code == 202, r.text
    with app_db.SessionLocal() as db:
        scan = db.get(Scan, r.json()["scan_id"])
        assert scan.llm_provider == "bedrock"
        assert "haiku" in (scan.llm_model or "")


# ---- DAST-05-020 ------------------------------------------------------------------------------


def test_presets_map_to_the_documented_budgets(client, project_id):
    def effective(**kw):
        return stored(post(client, project_id, **kw).json()["scan_id"])["dast_effective"]

    light, standard, deep = effective(intensity="light"), effective(), effective(intensity="deep")
    for key, value in DEFAULT_LIGHT.items():
        assert light[key] == value and light["budget_sources"][key] == "preset"
    for key, value in DEFAULT_DEEP.items():
        assert deep[key] == value
    assert standard["intensity"] == "standard" and standard["max_pages"] == settings.dast_max_pages
    assert standard["max_targets"] == settings.dast_max_targets


def test_explicit_values_beat_the_preset(client, project_id):
    eff = stored(post(client, project_id, intensity="light", max_pages=77, max_targets=9, rate_limit_per_sec=1.5).json()["scan_id"])["dast_effective"]
    assert eff["max_pages"] == 77 and eff["budget_sources"]["max_pages"] == "request"
    assert eff["max_targets"] == 9 and eff["max_depth"] == DEFAULT_LIGHT["max_depth"] and eff["budget_sources"]["max_depth"] == "preset"
    assert eff["rate_limit_per_sec"] == 1.5 and eff["rate_limit_source"] == "request"


def test_preset_values_are_configurable(client, project_id, monkeypatch):
    monkeypatch.setattr(settings, "dast_preset_light", {"max_pages": 12})
    assert stored(post(client, project_id, intensity="light").json()["scan_id"])["dast_effective"]["max_pages"] == 12


def test_the_snapshot_does_not_change_when_global_settings_do(client, project_id, monkeypatch):
    scan_id = post(client, project_id, rule_packs=["owasp-web-top10"]).json()["scan_id"]
    before = json.dumps(stored(scan_id)["dast_effective"], sort_keys=True), json.dumps(stored(scan_id)["dast_rule_set"], sort_keys=True)
    monkeypatch.setattr(settings, "dast_max_pages", 5)
    monkeypatch.setattr(settings, "dast_rate_limit_per_sec", 99.0)
    client.patch("/dast/rules", json={"packs": {"passive-only": True}}, headers=HDR)
    client.get(f"/scans/{scan_id}/results", headers=HDR)
    after = json.dumps(stored(scan_id)["dast_effective"], sort_keys=True), json.dumps(stored(scan_id)["dast_rule_set"], sort_keys=True)
    assert before == after
    newer = stored(post(client, project_id).json()["scan_id"])["dast_effective"]
    assert newer["max_pages"] == 5 and newer["rate_limit_per_sec"] == 99.0


def test_the_snapshot_holds_what_the_scan_ran_with_and_no_secret(client, project_id):
    scan_id = post(client, project_id, identities=IDENTITIES, method_policy="opt_in_mutating", target_disposable=True).json()["scan_id"]
    eff = stored(scan_id)["dast_effective"]
    assert eff["safe_mode"] is False and eff["method_policy"] == "opt_in_mutating" and eff["allow_state_changing"] is True
    assert eff["second_identity"] is True and eff["rule_packs"] == ["owasp-api-top10-2023", "owasp-web-top10"]
    assert eff["rule_checks_enabled"] > 0 and eff["catalog_version"] and set(eff["model_routing"]) == {
        "fingerprint", "crawl_plan", "login_selectors", "construct", "rule", "narrate"}
    blob = json.dumps(eff)
    assert not any(secret in blob for secret in (PASSWORD, TOKEN, COOKIE)) and "password" not in blob.lower()
    safe = stored(post(client, project_id).json()["scan_id"])["dast_effective"]
    assert safe["safe_mode"] is True and safe["method_policy"] == "safe"


def test_the_scan_api_returns_the_snapshot_and_the_skipped_degraded_list(client, project_id):
    scan_id = post(client, project_id, identities=IDENTITIES[:1]).json()["scan_id"]  # one authenticated identity
    body = client.get(f"/scans/{scan_id}/results", headers=HDR).json()
    assert body["dast_effective"]["intensity"] == "standard" and body["dast_rule_set"]["packs"]
    by_id = {e["check_id"]: e for e in body["dast_skipped_degraded"]}
    assert by_id["dast-bola"]["status"] == "degraded" and "no second identity" in by_id["dast-bola"]["reason"]
    two = post(client, project_id, identities=IDENTITIES[:2]).json()["scan_id"]
    assert "dast-bola" not in {e["check_id"] for e in client.get(f"/scans/{two}/results", headers=HDR).json()["dast_skipped_degraded"]}
    sast = client.post("/scans", json={"project_id": project_id, "scan_type": "sast"}, headers=HDR).json()["scan_id"]
    assert client.get(f"/scans/{sast}/results", headers=HDR).json().get("dast_effective") is None


# ---- DAST-06-010: credentials never survive ---------------------------------------------------


def test_holder_is_empty_after_success_failure_and_cancel(client, project_id, monkeypatch):
    from app.services import credential_holder

    holders: list = []
    real = credential_holder.InMemoryCredentialHolder

    class Spy(real):  # type: ignore[misc, valid-type]
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            holders.append(self)

    monkeypatch.setattr(scan_runner, "InMemoryCredentialHolder", Spy)

    post(client, project_id, identities=IDENTITIES)  # success
    from app.services import engine_adapter

    original = engine_adapter.run_dast_scan

    def failing(**kwargs):
        raise RuntimeError(f"login failed with password {PASSWORD} and token {TOKEN}")

    monkeypatch.setattr(engine_adapter, "run_dast_scan", failing)
    failed = post(client, project_id, identities=IDENTITIES).json()["scan_id"]  # failure

    def cancelling(**kwargs):
        scan_runner.request_cancel(kwargs["scan_id"])
        return original(**kwargs)

    monkeypatch.setattr(engine_adapter, "run_dast_scan", cancelling)
    cancelled = post(client, project_id, identities=IDENTITIES).json()["scan_id"]  # cancel
    assert len(holders) == 3 and all(h.is_empty() and h.secrets() == [] for h in holders)

    with app_db.SessionLocal() as db:
        statuses = {s.id: s.status for s in db.query(Scan)}
        assert statuses[failed] == "failed" and statuses[cancelled] == "cancelled"
        failed_scan = db.get(Scan, failed)
        assert PASSWORD not in (failed_scan.message or "") and TOKEN not in (failed_scan.message or "")
    log_text = client.get(f"/scans/{failed}/logs", headers=HDR).text
    assert PASSWORD not in log_text and TOKEN not in log_text and "hunter" not in log_text


def test_engine_output_is_redacted_before_it_is_stored(client, project_id, monkeypatch):
    from app.services import engine_adapter

    def leaky(**kwargs):
        print(f"debug dump: {PASSWORD} / {TOKEN} / {COOKIE}")
        return {"discovery": {"target_url": URL, "connection_ok": True, "login_error": f"bad credentials {PASSWORD}",
                              "pages": [{"url": f"{URL}/?t={TOKEN}"}], "api_calls": []}}

    monkeypatch.setattr(engine_adapter, "run_dast_scan", leaky)
    scan_id = post(client, project_id, identities=IDENTITIES).json()["scan_id"]
    everything = json.dumps(stored(scan_id)) + client.get(f"/scans/{scan_id}/logs", headers=HDR).text + client.get(f"/scans/{scan_id}/narration", headers=HDR).text
    assert not any(secret in everything for secret in (PASSWORD, TOKEN, COOKIE))
    assert "[REDACTED]" in everything


def test_a_restart_that_loses_the_credentials_fails_the_scan(client, project_id, monkeypatch):
    monkeypatch.setattr(scan_runner, "set_dast_credentials", lambda scan_id, creds: None)  # as if the process restarted
    scan_id = post(client, project_id, identities=IDENTITIES).json()["scan_id"]
    status = client.get(f"/scans/{scan_id}/status", headers=HDR).json()
    assert status["status"] == "failed" and "credentials" in status["message"] and "Admin A" in status["message"]
    anon_only = post(client, project_id).json()["scan_id"]  # nothing to lose
    assert client.get(f"/scans/{anon_only}/status", headers=HDR).json()["status"] == "success"


# ---- DAST-05-050 / DAST-06-050 -----------------------------------------------------------------


def test_cancelling_a_finished_dast_scan_is_a_clear_no_op(client, project_id):
    scan_id = post(client, project_id).json()["scan_id"]
    r = client.post(f"/scans/{scan_id}/cancel", headers=HDR)
    assert r.status_code == 200 and r.json()["status"] == "success" and "Nothing to cancel" in r.json()["message"]
    assert r.json() == client.post(f"/scans/{scan_id}/cancel", headers=HDR).json()  # and again: same answer


def test_a_cancelled_dast_scan_stays_cancelled_and_keeps_its_findings(client, project_id, monkeypatch):
    from app.services import engine_adapter

    original = engine_adapter.run_dast_scan

    def cancelling(**kwargs):
        result = original(**kwargs)
        scan_runner.request_cancel(kwargs["scan_id"])  # cancelled just before the engine returns
        return result

    monkeypatch.setattr(engine_adapter, "run_dast_scan", cancelling)
    scan_id = post(client, project_id).json()["scan_id"]
    assert client.get(f"/scans/{scan_id}/status", headers=HDR).json()["status"] == "cancelled"
    assert client.get(f"/scans/{scan_id}/findings", headers=HDR).json()["findings"]  # written before the cancel: kept
    assert client.post(f"/scans/{scan_id}/cancel", headers=HDR).json()["status"] == "cancelled"
    assert client.get(f"/scans/{scan_id}/status", headers=HDR).json()["status"] == "cancelled"  # never becomes success


def test_a_restart_fails_interrupted_dast_scans_without_resuming_them(client, project_id):
    with_secret = post(client, project_id, identities=IDENTITIES[:1]).json()["scan_id"]
    without = post(client, project_id).json()["scan_id"]
    done = post(client, project_id).json()["scan_id"]
    with app_db.SessionLocal() as db:  # pretend the first two were mid-run when the process died
        for sid in (with_secret, without):
            scan = db.get(Scan, sid)
            scan.status, scan.progress, scan.message = "running", 40, None
        db.commit()
    assert scan_runner.recover_interrupted_dast_scans() == 2
    status = lambda sid: client.get(f"/scans/{sid}/status", headers=HDR).json()  # noqa: E731
    assert status(with_secret)["status"] == "failed" and "credentials were lost" in status(with_secret)["message"]
    assert status(without)["status"] == "failed" and "interrupted" in status(without)["message"]
    assert status(done)["status"] == "success" and scan_runner.recover_interrupted_dast_scans() == 0
