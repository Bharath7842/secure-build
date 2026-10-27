"""Narration and progress (DAST-12-010 .. -030): stage banners and progress markers, the narration
timeline with its template fallback and guards, and the cheap live counters."""

from __future__ import annotations

import re
import time

import pytest
from fastapi.testclient import TestClient

from app import db as app_db
from app.config import settings
from app.dast.domain.entities import Location
from app.dast.domain.identities import build_identities
from app.main import app
from app.models import DastRequestAudit, Scan
from app.services import dast_narration, dast_summary, scan_runner
from app.services.scan_progress import PROGRESS_MARKERS, infer_progress_from_lines
from tests.dast_fixtures import FakeModelGateway
from tests.test_dast_authz import SECRETS, authz_target
from tests.test_dast_engine import Harness, default_rule_set

from tests.auth_helpers import ADMIN_HEADERS  # noqa: E402

HDR = ADMIN_HEADERS

# ---- banners and markers (DAST-12-010) ----------------------------------------------------------------------

LABELS = ["checking connection", "fingerprinting", "logging in", "crawling", "importing schemas", "passive analysis", "planning tests", "testing apis", "probing browser inputs", "checking authorization", "finishing"]


def progress_of(label: str) -> int:
    return infer_progress_from_lines([f"### DAST: {label}"], floor=10)


@pytest.mark.unit
def test_every_label_has_a_marker_and_progress_never_goes_backwards():
    values = [progress_of(label) for label in LABELS]
    assert all(v >= 10 for v in values) and len(set(values)) > 6
    assert values == sorted(values)  # increasing in the order the stages run
    assert progress_of("finishing") == 95 and max(values) < 100  # 100 is only ever set on success
    lines = [f"### DAST: {label}" for label in LABELS]
    assert infer_progress_from_lines(lines, floor=10) == progress_of("finishing")
    assert infer_progress_from_lines(list(reversed(lines)), floor=10) == progress_of("finishing")  # a late older label does not lower it
    assert infer_progress_from_lines(["### DAST: made-up stage"], floor=42) == 42  # unknown labels do nothing
    assert infer_progress_from_lines(["### DAST: made-up stage", "### DAST: passive analysis"], floor=10) == progress_of("passive analysis")


@pytest.mark.unit
def test_logs_persisted_before_the_renames_still_resolve():
    historical = ["### DAST: checking connection", "### DAST: authenticating", "### DAST: classifying login", "### DAST: logging in", "### DAST: crawling", "### DAST: ingesting schemas", "### DAST: testing apis", "### DAST: summarizing"]
    assert infer_progress_from_lines(historical, floor=10) == 95
    assert progress_of("ingesting schemas") == progress_of("importing schemas") and progress_of("summarizing") == progress_of("finishing")
    labels = {needle for needle, _ in PROGRESS_MARKERS}
    assert {"### DAST: authenticating", "### DAST: ingesting schemas", "### DAST: summarizing"} <= labels  # old ones are kept, not renamed away


@pytest.mark.integration
def test_each_stage_prints_exactly_one_banner_in_order(capsys):
    target = authz_target()
    harness = Harness(target, build_identities([{"label": "Root", "role": "Admin", "auth_method": "token"}]), {"Root": SECRETS["Root"]}, gateway=FakeModelGateway(strict=False), rule_set=default_rule_set())
    harness.run(run_analysis=True)
    banners = re.findall(r"^### DAST: (.+)$", capsys.readouterr().out, flags=re.MULTILINE)
    assert banners == ["checking connection", "fingerprinting", "logging in", "importing schemas", "passive analysis", "testing apis", "probing browser inputs", "checking authorization", "finishing"]
    assert len(banners) == len(set(banners))
    assert set(banners) <= set(LABELS)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    monkeypatch.setattr(settings, "use_mock_engine", True)
    monkeypatch.setattr(settings, "scan_logs_dir", str(tmp_path / "scan_logs"))
    app_db.init_db(f"sqlite:///{(tmp_path / 'p.db').as_posix()}")
    return TestClient(app)


@pytest.fixture()
def project_id(client):
    return client.post("/projects", json={"name": "progress", "default_git_url": ""}, headers=HDR).json()["id"]


def make_scan(client, project_id):
    body = {"project_id": project_id, "scan_type": "dast", "dast": {"target_url": "http://localhost:3000", "authorized": True}}
    return client.post("/scans", json=body, headers=HDR).json()["scan_id"]


@pytest.mark.integration
def test_progress_is_100_only_on_success(client, project_id, monkeypatch):
    ok = make_scan(client, project_id)
    assert client.get(f"/scans/{ok}/status", headers=HDR).json()["progress"] == 100
    # a failed scan (the live engine is requested but disabled) keeps its last progress
    monkeypatch.setattr(settings, "use_mock_engine", False)
    monkeypatch.setattr(settings, "run_dast", False)
    monkeypatch.setenv("USE_MOCK_ENGINE", "false")
    failed = make_scan(client, project_id)
    for _ in range(100):  # the live engine runs on a thread
        status = client.get(f"/scans/{failed}/status", headers=HDR).json()
        if status["status"] != "running":
            break
        time.sleep(0.05)
    assert status["status"] == "failed" and status["progress"] < 100
    # a cancelled DAST scan too
    with app_db.SessionLocal() as db:
        scan = db.get(Scan, ok)
        scan.status, scan.progress = "running", 60
        db.commit()
        scan_runner._mark_cancelled(db, ok)
        db.refresh(scan)
        assert scan.status == "cancelled" and scan.progress == 60


# ---- narration (DAST-12-020) -------------------------------------------------------------------------------------


def log_for(*labels):
    lines = []
    for label in labels:
        lines += [f"### DAST: {label}", f"  {label}: working"]
    return lines


def mock_discovery(client, project_id):
    scan_id = make_scan(client, project_id)
    return client.get(f"/scans/{scan_id}/results", headers=HDR).json()["discovery"]


@pytest.mark.integration
def test_every_new_stage_has_a_template_narration_when_the_model_is_off(client, project_id, monkeypatch):
    monkeypatch.setattr(dast_narration, "_llm_enabled", lambda: False)
    discovery = mock_discovery(client, project_id)
    payload = dast_narration.get_narration("s1", "success", log_for(*LABELS), discovery, {"target_url": "http://localhost:3000"})
    steps = {s["id"]: s for s in payload["steps"]}
    assert list(steps) == ["connection", "auth", "discovery", "passive", "testing", "browser", "authorization", "analysis"]
    assert "inert markers" in steps["browser"]["narration"]
    assert all(s["status"] == "done" and s["source"] == "template" and s["narration"] for s in steps.values())
    assert "recorded" in steps["passive"]["narration"] and "without sending" in steps["passive"]["narration"]
    assert "replayed" in steps["authorization"]["narration"]
    assert "Origin header" in " ".join(steps["passive"]["reasoning"])  # the not-assessable CORS note surfaces
    assert not payload["pending"] and not payload["llm_enabled"]


@pytest.mark.unit
def test_templates_cover_the_skipped_and_empty_cases():
    t = lambda step, d: dast_narration._template(step, d, {"target_url": "http://x"}, "done")  # noqa: E731
    assert "No passive checks were enabled" in t("passive", {})["narration"]
    assert "did not run the authorization checks: no second identity" in t("authorization", {"authorization": {"ran": False, "degraded_reason": "no second identity"}})["narration"]
    untested = t("testing", {"active_testing": {"not_tested": [{"label": "POST /a", "reason": "not tested: safe mode"}]}})
    assert "not tested: safe mode" in untested["narration"]
    tested = t("testing", {"analysis_summary": {"apis_tested": 2, "fail": 1, "pass": 3}, "active_testing": {"guardrail_overrides": 2}})
    assert "2 REST APIs" in tested["narration"] and "raised 2" in " ".join(tested["reasoning"])


@pytest.mark.unit
def test_a_gateway_failure_uses_the_template_and_raw_model_output_is_never_shown(monkeypatch):
    gateway = FakeModelGateway(strict=False)
    monkeypatch.setattr(dast_narration, "_gateway", gateway)
    assert dast_narration._call_llm("evidence") is None  # the gateway fell back: no model prose
    for raw in (
        '{"narration": "{\\"tests\\": [{\\"check_id\\": \\"dast-sqli\\"}]}"}',
        '{"narration": "[thinking] we need to classify the login page"}',
        '{"narration": "```json\\n{}\\n```"}',
        '{"narration": "Traceback (most recent call last): boom"}',
        '{"narration": "### DAST: testing apis"}',
        '{"narration": "ok", "reasoning": ["[planner] chose /admin", "{\\"verdict\\": \\"FAIL\\"}"]}',
    ):
        parsed = dast_narration.parse_narration_response(raw)
        assert parsed is None or parsed["reasoning"] == [] and parsed["narration"] == "ok", raw
    good = dast_narration.parse_narration_response('{"narration": "I found 3 pages.", "reasoning": ["forms matter", "{\\"x\\": 1}"]}')
    assert good == {"narration": "I found 3 pages.", "reasoning": ["forms matter"]}


@pytest.mark.unit
def test_credentials_never_appear_in_the_narration_input_or_output(monkeypatch):
    secret_shapes = "sk-ant-abcdefghijklmnop1234 Bearer abcdefghijklmnopqrstuvwxyz0123 AKIAIOSFODNN7EXAMPLE"
    prompt = dast_narration._build_prompt("Testing", [f"  sent header with {secret_shapes}"], {}, "testing")
    for secret in ("sk-ant-abcdefghijklmnop1234", "abcdefghijklmnopqrstuvwxyz0123", "AKIAIOSFODNN7EXAMPLE"):
        assert secret not in prompt
    assert "untrusted" in prompt
    reply = '{"narration": "I used sk-ant-abcdefghijklmnop1234 to sign in.", "reasoning": ["key AKIAIOSFODNN7EXAMPLE leaked"]}'
    parsed = dast_narration.parse_narration_response(reply)
    assert "sk-ant" not in parsed["narration"] and "AKIA" not in parsed["reasoning"][0]


@pytest.mark.integration
def test_narration_is_cached_until_new_log_lines_arrive(client, project_id, monkeypatch):
    monkeypatch.setattr(dast_narration, "_llm_enabled", lambda: False)
    discovery = mock_discovery(client, project_id)
    calls = []
    real = dast_narration._template
    monkeypatch.setattr(dast_narration, "_template", lambda *a, **k: calls.append(a[0]) or real(*a, **k))
    lines = log_for("checking connection", "logging in")
    first = dast_narration.get_narration("cache-scan", "running", lines, discovery, {})
    made = len(calls)
    again = dast_narration.get_narration("cache-scan", "running", lines, discovery, {})
    assert len(calls) == made and [s["narration"] for s in again["steps"]] == [s["narration"] for s in first["steps"]]
    changed = [lines[0], lines[1], "  late evidence for the first step", *lines[2:]]
    dast_narration.get_narration("cache-scan", "running", changed, discovery, {})
    assert len(calls) > made  # a changed log regenerates the affected step
    persisted = dast_narration.persistable(again)
    reuse = dast_narration.get_narration("cache-scan-2", "running", lines, discovery, {}, persisted=persisted)
    assert len(calls) > made and [s["narration"] for s in reuse["steps"]] == [s["narration"] for s in first["steps"]]


# ---- live counters (DAST-12-030) ----------------------------------------------------------------------------------


@pytest.mark.integration
def test_a_finished_scan_reports_counters_that_match_its_findings(client, project_id):
    scan_id = make_scan(client, project_id)
    body = client.get(f"/scans/{scan_id}/summary", headers=HDR).json()
    findings = client.get(f"/scans/{scan_id}/findings", headers=HDR).json()
    assert body["scan_id"] == scan_id and body["running"] is False and body["status"] == "success"
    assert body["findings"]["by_verdict"]["true_positive"] == findings["tp_count"] and body["findings"]["by_verdict"]["unverified"] == findings["unverified_count"]
    assert sum(body["findings"]["by_severity"].values()) == findings["tp_count"] and body["findings"]["total"] == findings["total_count"]
    assert body["pages_crawled"] == 3 and body["endpoints_discovered"] == 3 and body["tests_run"] == 3
    assert {"requests_sent", "requests_denied", "skipped_checks", "model_calls", "model_cost_usd"} <= set(body)
    assert body["model_calls"] == 11  # the mock engine's fixed usage summary
    with app_db.SessionLocal() as db:
        assert "dast_summary" in db.get(Scan, scan_id).metadata_json  # stored once the scan ended


@pytest.mark.integration
def test_a_running_scan_reports_live_values_that_change_as_it_progresses(client, project_id):
    from app.dast.runtime import LiveCounters

    scan_id = make_scan(client, project_id)
    with app_db.SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        meta = dict(scan.metadata_json)
        meta.pop("dast_summary", None)
        scan.metadata_json, scan.status = meta, "running"
        db.commit()
    counters, audit, usage = LiveCounters(), {"sent": 0, "denied": 0}, {"call_count": 0, "cost_usd": 0.0}
    dast_summary.registry.register(scan_id, dast_summary.LiveScan(counters.snapshot, lambda: dict(audit), lambda: dict(usage)))
    try:
        first = client.get(f"/scans/{scan_id}/summary", headers=HDR).json()
        assert first["running"] is True and first["pages_crawled"] == 0 and first["requests_sent"] == 0 and first["tests_run"] == 0
        counters.set("pages", 12), counters.set("endpoints", 40), counters.add("tests", 5), audit.update(sent=90, denied=3), usage.update(call_count=7, cost_usd=0.0123)
        second = client.get(f"/scans/{scan_id}/summary", headers=HDR).json()
        assert (second["pages_crawled"], second["endpoints_discovered"], second["tests_run"], second["requests_sent"], second["requests_denied"]) == (12, 40, 5, 90, 3)
        assert second["model_calls"] == 7 and second["model_cost_usd"] == pytest.approx(0.0123)
    finally:
        dast_summary.registry.unregister(scan_id)


@pytest.mark.integration
def test_the_summary_is_cheap_on_a_large_audit_table_and_consistent_after_cancel(client, project_id):
    scan_id = make_scan(client, project_id)
    with app_db.SessionLocal() as db:
        db.bulk_insert_mappings(
            DastRequestAudit,
            [{"scan_id": scan_id, "seq": i, "method": "GET", "url": f"http://localhost:3000/p/{i}", "allowed": i % 50 != 0, "timestamp": __import__("datetime").datetime.now(__import__("datetime").timezone.utc)} for i in range(1, 30001)],
        )
        scan = db.get(Scan, scan_id)
        meta = dict(scan.metadata_json)
        meta.pop("dast_summary", None)
        scan.metadata_json, scan.status = meta, "running"
        db.commit()
        scan_runner._mark_cancelled(db, scan_id)
        dast_summary.finalize(db, db.get(Scan, scan_id))  # the end-of-scan count, done once
    started = time.perf_counter()
    for _ in range(20):
        body = client.get(f"/scans/{scan_id}/summary", headers=HDR).json()
    per_call = (time.perf_counter() - started) / 20
    assert body["status"] == "cancelled" and body["running"] is False and body["requests_sent"] == 30000 - 600 and body["requests_denied"] == 600
    assert per_call < 0.25, per_call  # baseline: a few milliseconds; the table is never scanned while polling
    assert client.get("/scans/zzz/summary", headers=HDR).status_code == 404
