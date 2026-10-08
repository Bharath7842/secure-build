"""Training-data capture with controls (DAST-16-050): off by default, scrubbed of identifying and
credential content, only agreeing records, never a rejected input, restricted and audited reads, and
export to the JSONL format with a dataset version."""

from __future__ import annotations

import json

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app import db as app_db
from app.config import settings
from app.dast import active
from app.dast.domain import training as T
from app.dast.domain.entities import CheckVerdict
from app.dast.domain.inventory import observed
from app.main import app
from app.models import DastTrainingAudit, DastTrainingExample, Project
from app.services import dast_training, engine_adapter
from tests.dast_fixtures import FakeModelGateway, FakeTarget
from tests.test_dast_active import SQLI, harness_steps, script_construct
from tests.test_dast_engine import BASE

pytestmark = pytest.mark.integration

ADMIN = "training-admin-token-123"
HOST = "target.test"
SECRET = "sess-9f8e7d6c5b4a3210fedcba98"


# ---- scrubbing, agreement, balancing (pure) --------------------------------------------------------------------


def test_scrubbing_removes_hosts_addresses_credentials_tokens_and_identifiers():
    raw = (
        f"GET https://app.target.test:8443/users/12345678?x=1 from 10.2.3.4 and fe80::1ff:fe23:4567:890a user bob@corp.example "
        f"Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345 "
        "id 3f2b8c1e-aaaa-4bbb-8ccc-0123456789ab hash 0123456789abcdef0123456789abcdef01 token ghp_" + "a" * 36 + f" key sk-ant-abcdefghijklmnop1234 mine {SECRET} "
        f"Set-Cookie: session={SECRET}; HttpOnly"
    )
    out = T.scrub_text(raw, hosts=["app.target.test", "target.test"], secrets=[SECRET])
    for leaked in ("target.test", "10.2.3.4", "fe80::", "bob@corp", "abcdefghijklmnopqrstuvwxyz012345", SECRET, "3f2b8c1e", "0123456789abcdef0123", "ghp_aaaa", "sk-ant", "12345678"):
        assert leaked not in out, leaked
    assert "<host>" in out and "<ip>" in out and "<email>" in out and "<id>" in out and "<secret>" in out
    assert "GET https://<host>" in out  # the shape of the request survives


def test_scrubbing_walks_nested_data_and_keeps_the_signal_names():
    data = {"input": {"signals": ["db_error_surfaced"], "test": {"body_excerpt": "error at 192.168.1.5 for a@b.example", "status": 500}}}
    out = T.scrub_value(data)
    assert out["input"]["signals"] == ["db_error_surfaced"] and out["input"]["test"]["status"] == 500 and "192.168" not in json.dumps(out) and "a@b.example" not in json.dumps(out)


@pytest.mark.parametrize(
    "proposed, final, signals, expected",
    [
        ("FAIL", "FAIL", ["db_error_surfaced"], True), ("PASS", "PASS", [], True), ("INCONCLUSIVE", "INCONCLUSIVE", [], True),
        ("FAIL", "FAIL", [], True),  # the model's FAIL stands without a proving signal
        ("FAIL", "INCONCLUSIVE", [], False),  # leftover disagreement
        ("PASS", "FAIL", ["db_error_surfaced"], False),  # a signal overrode the model's PASS
        ("PASS", "PASS", ["db_error_surfaced"], False), ("FAIL", "BANANA", [], False),
    ],
)
def test_only_records_where_the_model_and_the_detectors_agree_qualify(proposed, final, signals, expected):
    assert T.agrees(proposed=proposed, final=final, signals=signals) is expected


def test_balancing_downsamples_to_the_smallest_class_deterministically():
    examples = [{"n": i} for i in range(10)]
    labels = ["fail"] * 2 + ["pass"] * 5 + ["inconclusive"] * 3
    kept = T.balance(examples, labels, seed=1)
    assert len(kept) == 6 and kept == T.balance(examples, labels, seed=1)
    kept_labels = [labels[e["n"]] for e in kept]
    assert {label: kept_labels.count(label) for label in T.LABELS} == {"fail": 2, "pass": 2, "inconclusive": 2}
    assert T.balance([], []) == []


def test_the_dataset_version_changes_with_the_content_and_the_jsonl_matches_the_sample_format():
    a, b = [{"task": "rule", "input": {}, "output": {"verdict": "PASS"}}], [{"task": "rule", "input": {}, "output": {"verdict": "FAIL"}}]
    assert T.dataset_version(a, "20261007") != T.dataset_version(b, "20261007") and T.dataset_version(a, "20261007").startswith("20261007-1-")
    ex = T.rule_example(check_id="dast-sqli", target="GET /api/p", signals=["db_error_surfaced"], baseline={"status": 200, "len": 5}, test={"status": 500, "len": 9, "body_excerpt": "x"}, verdict="fail", severity="HIGH", confidence="high", finding="f")
    sample = json.loads(open(__import__("pathlib").Path(__file__).resolve().parents[2] / "spec" / "dast_training_samples.jsonl").readline())
    assert set(ex) == set(sample) == {"task", "input", "output"} and set(ex["input"]) == set(sample["input"]) and set(ex["output"]) == set(sample["output"])
    assert ex["output"]["verdict"] == "FAIL" and ex["output"]["severity"] == "high" and ex["output"]["confidence"] == "HIGH"
    assert T.to_jsonl(a).endswith("\n") and json.loads(T.to_jsonl(a).splitlines()[0]) == a[0]


# ---- the sink ---------------------------------------------------------------------------------------------------


@pytest.fixture()
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    monkeypatch.setattr(settings, "use_mock_engine", True)
    monkeypatch.setattr(settings, "scan_logs_dir", str(tmp_path / "logs"))
    monkeypatch.setattr(settings, "dast_training_admin_token", SecretStr(ADMIN))
    app_db.init_db(f"sqlite:///{(tmp_path / 't.db').as_posix()}")
    return app_db.SessionLocal


def vulnerable() -> FakeTarget:
    t = FakeTarget()
    t.route("GET", "/api/search", lambda r: httpx.Response(500, text=f"You have an error in your SQL syntax near x on 10.9.8.7 from {HOST} token {SECRET}", headers={"content-type": "text/html"}) if "'" in r.url.params.get("q", "") else httpx.Response(200, json={"results": []}))
    t.add_json("/api/safe", {"ok": True})
    return t


def run_with_sink(rule_reply, *, sink=None, endpoint=None, construct=SQLI):
    target = vulnerable()
    gateway = FakeModelGateway(strict=False)
    script_construct(gateway, construct)
    gateway.script("rule", rule_reply)
    steps, _ = harness_steps(target, gateway)
    outcome = active.run_target(endpoint or observed("GET", f"{BASE}/api/search?q=1", kind="api"), steps, max_tests=3, log=lambda *_: None)
    if sink is not None:
        sink(outcome, steps.checks)
    return outcome


def stored(db):
    with db() as session:
        return [(r.task, r.label, r.example) for r in session.query(DastTrainingExample).order_by(DastTrainingExample.id)]


def make_sink(db, project_id="p1", scan_id="s1"):
    return dast_training.TrainingSink(project_id, scan_id, target_url=f"http://{HOST}:3000", secrets=lambda: [SECRET])


def test_an_agreeing_confirmed_test_is_stored_as_a_rule_and_a_construct_example_without_identifiers(db):
    run_with_sink({"verdict": "FAIL", "finding": f"db error from {HOST}", "severity": "high", "confidence": "high"}, sink=make_sink(db))
    rows = stored(db)
    assert {(task, label) for task, label, _ in rows} == {("rule", "fail"), ("construct", "fail")}
    blob = json.dumps([e for *_, e in rows])
    for leaked in (HOST, "10.9.8.7", SECRET):
        assert leaked not in blob, leaked
    rule = next(e for t, _, e in rows if t == "rule")
    assert rule["input"]["signals"] == ["db_error_surfaced"] and rule["output"]["verdict"] == "FAIL" and "/api/search" in rule["input"]["target"] and rule["input"]["target"].startswith("GET ")
    construct = next(e for t, _, e in rows if t == "construct")
    assert construct["output"]["tests"][0]["input"] == "1'" and construct["output"]["tests"][0]["check_id"] == "dast-sqli"


def test_a_disagreement_between_the_model_and_the_detectors_is_not_captured(db):
    sink = make_sink(db)
    run_with_sink({"verdict": "PASS", "finding": "nothing"}, sink=sink)  # a signal overrode the model's PASS
    assert stored(db) == [] and sink.captured == 0 and sink.skipped >= 1


def test_pass_and_inconclusive_agreements_are_captured_with_their_labels(db):
    sink = make_sink(db)
    safe = observed("GET", f"{BASE}/api/safe?q=1", kind="api")
    run_with_sink({"verdict": "PASS", "finding": "clean"}, sink=sink, endpoint=safe)
    run_with_sink({"verdict": "INCONCLUSIVE", "finding": "unclear"}, sink=sink, endpoint=safe)
    assert {label for _, label, _ in stored(db)} == {"pass"}


def test_an_input_the_validator_rejects_is_never_stored(db):
    sink = make_sink(db)
    outcome = run_with_sink({"verdict": "FAIL"}, endpoint=observed("GET", f"{BASE}/api/search?q=1", kind="api"), construct={**SQLI, "input": "1; DROP TABLE users--"})
    assert outcome.records == [] and outcome.dropped_unsafe == 1
    sink(outcome, {})  # nothing to capture: the unsafe input was dropped before it was ever sent
    assert stored(db) == []
    ok = run_with_sink({"verdict": "FAIL", "finding": "x"})
    ok.records[0].input = "x; rm -rf /"  # even if a record somehow carried one, the sink re-checks and refuses it
    steps, _ = harness_steps(vulnerable(), FakeModelGateway(strict=False))
    sink(ok, steps.checks)
    assert stored(db) == []


def test_a_per_project_storage_bound_applies_to_each_label(db, monkeypatch):
    monkeypatch.setattr(dast_training, "MAX_PER_LABEL_PER_PROJECT", 1)
    sink = make_sink(db)
    for _ in range(3):
        run_with_sink({"verdict": "FAIL", "finding": "db error"}, sink=sink)
    assert len([1 for _, label, _ in stored(db) if label == "fail"]) == 1


def test_capture_is_off_unless_the_project_opted_in(db):
    with db() as session:
        project = Project(name="cap", default_git_url="")
        session.add(project)
        session.commit()
        assert project.training_capture_enabled is False
        assert engine_adapter._training_sink(project, "s1", f"http://{HOST}", None) is None
        project.training_capture_enabled = True
        assert isinstance(engine_adapter._training_sink(project, "s1", f"http://{HOST}", None), dast_training.TrainingSink)
        assert engine_adapter._training_sink(None, "s1", f"http://{HOST}", None) is None and engine_adapter._training_sink(project, None, f"http://{HOST}", None) is None


# ---- restricted, audited access -------------------------------------------------------------------------------------

HDR = {"Authorization": f"Bearer {settings.sast_api_token}"}
TRAINER = {**HDR, "X-Training-Admin-Token": ADMIN, "X-Training-Reader": "alice"}


@pytest.fixture()
def client(db):
    return TestClient(app)


def audit_rows(db):
    with db() as session:
        return [(r.reader, r.action, r.allowed) for r in session.query(DastTrainingAudit).order_by(DastTrainingAudit.at, DastTrainingAudit.id)]


def seed_examples(db, n_fail=4, n_pass=2, n_inc=3):
    with db() as session:
        for label, count in (("fail", n_fail), ("pass", n_pass), ("inconclusive", n_inc)):
            for i in range(count):
                session.add(DastTrainingExample(project_id="p1", scan_id="s1", task="rule", label=label, example={"task": "rule", "input": {"n": f"{label}{i}"}, "output": {"verdict": label.upper()}}))
        session.commit()


def test_an_unauthorized_read_is_denied_and_audited(client, db):
    seed_examples(db)
    for headers in (HDR, {**HDR, "X-Training-Reader": "mallory"}, {**HDR, "X-Training-Admin-Token": "wrong", "X-Training-Reader": "mallory"}, {**HDR, "X-Training-Admin-Token": ADMIN}):
        r = client.get("/dast/training/examples", headers=headers)
        assert r.status_code == 403 and "examples" not in r.text
    assert client.get("/dast/training/examples").status_code in (401, 403)  # not even the bearer token
    assert client.get("/dast/training/export.jsonl", headers={**HDR, "X-Training-Reader": "mallory"}).status_code == 403
    rows = audit_rows(db)
    assert len(rows) == 5 and not any(allowed for *_, allowed in rows) and ("mallory", "list", False) in rows and ("anonymous", "list", False) in rows


def test_without_a_configured_admin_token_nobody_can_read_or_enable(client, db, monkeypatch):
    monkeypatch.setattr(settings, "dast_training_admin_token", None)
    assert client.get("/dast/training/examples", headers={**HDR, "X-Training-Admin-Token": "", "X-Training-Reader": "alice"}).status_code == 403
    with db() as session:
        project = Project(name="p", default_git_url="")
        session.add(project)
        session.commit()
        pid = project.id
    assert client.patch(f"/projects/{pid}/dast-training", json={"enabled": True}, headers={**HDR, "X-Training-Admin-Token": "x", "X-Training-Reader": "alice"}).status_code == 403


def test_an_authorized_read_works_and_is_audited(client, db):
    seed_examples(db)
    body = client.get("/dast/training/examples", headers=TRAINER, params={"limit": 3}).json()
    assert len(body["examples"]) == 3 and body["next_after"] == body["examples"][-1]["id"] and {"id", "task", "label", "input", "output"} <= set(body["examples"][0])
    more = client.get("/dast/training/examples", headers=TRAINER, params={"limit": 100, "after": body["next_after"]}).json()
    assert len(more["examples"]) == 6 and more["next_after"] is None
    assert ("alice", "list", True) in audit_rows(db)
    log = client.get("/dast/training/audit", headers=TRAINER).json()["entries"]
    assert log[0]["reader"] == "alice" and log[0]["allowed"] is True and any(e["count"] == 3 for e in log)


def test_enabling_capture_needs_the_admin_token_and_is_audited(client, db):
    with db() as session:
        project = Project(name="opt", default_git_url="")
        session.add(project)
        session.commit()
        pid = project.id
    denied = client.patch(f"/projects/{pid}/dast-training", json={"enabled": True}, headers={**HDR, "X-Training-Reader": "mallory"})
    assert denied.status_code == 403
    ok = client.patch(f"/projects/{pid}/dast-training", json={"enabled": True}, headers=TRAINER)
    assert ok.status_code == 200 and ok.json()["training_capture_enabled"] is True
    with db() as session:
        assert session.get(Project, pid).training_capture_enabled is True
    assert ("alice", "enable", True) in audit_rows(db) and ("mallory", "enable", False) in audit_rows(db)
    assert client.patch(f"/projects/{pid}/dast-training", json={"enabled": False}, headers=TRAINER).json()["training_capture_enabled"] is False
    assert client.patch("/projects/none/dast-training", json={"enabled": True}, headers=TRAINER).status_code == 404


def test_export_is_balanced_jsonl_with_a_recorded_dataset_version(client, db):
    seed_examples(db, n_fail=4, n_pass=2, n_inc=3)
    r = client.get("/dast/training/export.jsonl", headers=TRAINER)
    lines = [json.loads(line) for line in r.text.splitlines()]
    assert r.headers["content-type"].startswith("application/x-ndjson") and len(lines) == 6  # 2 of each label: the smallest class
    verdicts = [line["output"]["verdict"] for line in lines]
    assert {v: verdicts.count(v) for v in ("FAIL", "PASS", "INCONCLUSIVE")} == {"FAIL": 2, "PASS": 2, "INCONCLUSIVE": 2}
    assert all(set(line) == {"task", "input", "output"} for line in lines)
    version = r.headers["x-dataset-version"]
    assert version.count("-") == 2 and r.headers["x-dataset-count"] == "6"
    assert client.get("/dast/training/export.jsonl", headers=TRAINER).headers["x-dataset-version"] == version  # same data, same version
    assert any(version in e["detail"] for e in client.get("/dast/training/audit", headers=TRAINER).json()["entries"])
    full = client.get("/dast/training/export.jsonl", headers=TRAINER, params={"balance": "false"})
    assert len(full.text.splitlines()) == 9 and full.headers["x-dataset-version"] != version
    assert client.get("/dast/training/export.jsonl", headers=TRAINER, params={"task": "bogus"}).status_code == 422
