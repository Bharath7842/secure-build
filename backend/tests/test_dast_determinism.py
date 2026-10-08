"""Determinism and offline guarantees (DAST-16-030): the same fake target scanned twice gives identical
findings and verdicts (also with parallel endpoint analysis), the whole offline pipeline runs with
sockets, subprocesses, Playwright and provider SDKs blocked, and "true_positive implies a detector
signal" holds across everything the pipeline writes."""

from __future__ import annotations

import builtins
import importlib
import json
import random
import socket
import subprocess
import sys

import httpx
import pytest
from fastapi.testclient import TestClient

from app import db as app_db
from app.config import settings
from app.dast import active
from app.dast.domain.detectors import signal_names
from app.dast.domain.entities import CheckVerdict, Endpoint
from app.dast.domain.interfaces import ModelReply
from app.dast.domain.inventory import observed
from app.dast.domain.mapping import finding_from_row
from app.dast.domain.ruleset import resolve_effective_rule_set
from app.dast.input_gate import InputGate
from app.dast.sessions import SessionStore
from app.main import app
from app.services.dast_catalog import default_catalog
from tests.dast_fixtures import FakeModelGateway, FakeTarget
from tools.dast_harness import determinism
from tests.test_dast_engine import BASE, Harness, default_rule_set
from tests.test_dast_authz import SECRETS, IDS, spec  # noqa: F401
from app.dast.domain.identities import build_identities

pytestmark = pytest.mark.integration

CATALOG = default_catalog()


@pytest.fixture(autouse=True)
def _fast(monkeypatch):
    from app.dast.nodes import crawl as crawl_node
    from app.dast.nodes import login as login_node

    monkeypatch.setattr(crawl_node.time, "sleep", lambda _s: None)
    monkeypatch.setattr(login_node, "extract_interactive_elements", lambda page: "[]")


class KeyedGateway(FakeModelGateway):
    """Replies by what the prompt is about, not by call order, so it is the same under any scheduling."""

    def __init__(self):
        super().__init__(strict=False)

    def complete(self, task, system, prompt, reply_schema, **kw):
        self.calls.append(type("C", (), {"task": task, "temperature": kw.get("temperature"), "prompt": prompt})())
        if task == "construct":
            if '"path_template": "/api/search"' in prompt:
                return ModelReply(data={"tests": [{"check_id": "dast-sqli", "parameter": "q", "location": "query", "input": "1'", "expected_signal": "sql error"}]})
            if '"path_template": "/api/note"' in prompt:
                return ModelReply(data={"tests": [{"check_id": "dast-xss", "parameter": "t", "location": "query", "input": "<i>x</i>", "expected_signal": "reflected"}]})
            return ModelReply(data={"tests": []})
        if task == "rule":
            return ModelReply(data={"verdict": "PASS" if "SQL syntax" not in prompt else "FAIL", "finding": "judged", "severity": "HIGH", "confidence": "HIGH", "evidence": "x"})
        return ModelReply(data={}, fallback_used=True)


def world() -> FakeTarget:
    t = FakeTarget()
    t.add_user("alice", "pw", role="user")
    t.add_page("/", "<html><body>home</body></html>", headers={"Server": "nginx/1.18.0"})
    t.route("GET", "/api/search", lambda r: httpx.Response(500, text="You have an error in your SQL syntax near ''' at line 1", headers={"content-type": "text/html"}) if "'" in r.url.params.get("q", "") else httpx.Response(200, json={"results": []}))
    t.route("GET", "/api/note", lambda r: httpx.Response(200, text=f"<p>{r.url.params.get('t', '')}</p>", headers={"content-type": "text/html"}))
    t.route("GET", "/api/admin/users", lambda r: httpx.Response(401) if t.user_for(r) is None else httpx.Response(200, json={"users": ["a", "b"], "count": 2}))
    t.set_openapi({"openapi": "3.0.0", "paths": {p: {"get": {"parameters": [{"name": n, "in": "query", "schema": {"type": "string"}}] if n else []}} for p, n in (("/api/search", "q"), ("/api/note", "t"), ("/api/admin/users", ""))}})
    return t


def scan(parallelism=1, gateway=None):
    identities = build_identities([spec("Root", "Admin"), spec("Alice", "User")])
    harness = Harness(world(), identities, {"Root": SECRETS["Root"], "Alice": SECRETS["Alice"]}, gateway=gateway or KeyedGateway(), rule_set=default_rule_set(), request={"model_parallelism": parallelism})
    discovery = harness.run(run_analysis=True)
    return discovery, harness


def normalized(harness, *, ignore_audit_refs=False):
    """The findings as written. `audit_ref` points at the request-audit row of the proving request; under
    parallel analysis the row numbers depend on how requests interleave, so a parallel comparison
    leaves that one pointer out (the serial comparison does not)."""
    rows = json.loads(json.dumps(harness.written, sort_keys=True, default=str))
    if ignore_audit_refs:
        for _, batch in rows:
            for row in batch:
                if row.get("evidence"):
                    row["evidence"]["audit_ref"] = ""
    return json.dumps(rows, sort_keys=True)


def test_the_same_target_scanned_twice_gives_identical_findings_and_verdicts():
    first, h1 = scan()
    second, h2 = scan()
    assert normalized(h1) == normalized(h2) and len(h1.written) >= 3
    for key in ("api_analysis", "inventory", "authorization", "passive_analysis", "active_testing"):
        assert json.dumps(first[key], sort_keys=True) == json.dumps(second[key], sort_keys=True), key
    rows = [r for _, rows in h1.written for r in rows]
    assert {r["rule_id"] for r in rows} >= {"dast-sqli", "dast-passive-tech-disclosure", "dast-bfla"} and not any("T" in str(r.get("timestamp", "")) for r in rows)


def test_parallel_analysis_gives_the_same_findings_as_serial_analysis():
    _, serial = scan(1)
    _, parallel = scan(3)
    assert normalized(serial, ignore_audit_refs=True) == normalized(parallel, ignore_audit_refs=True)
    for _ in range(3):  # and it does not depend on thread scheduling
        _, again = scan(3)
        assert normalized(again, ignore_audit_refs=True) == normalized(parallel, ignore_audit_refs=True)


def test_the_model_is_called_with_low_temperatures_so_runs_stay_close():
    gateway = KeyedGateway()
    scan(gateway=gateway)
    temps = {c.task: c.temperature for c in gateway.calls if c.task in ("construct", "rule")}
    assert temps == {"construct": active.CONSTRUCT_TEMPERATURE, "rule": active.RULE_TEMPERATURE} and active.RULE_TEMPERATURE == 0.0 and active.CONSTRUCT_TEMPERATURE <= 0.2


def test_prompts_are_identical_across_runs_few_shot_order_included():
    a, b = KeyedGateway(), KeyedGateway()
    scan(gateway=a)
    scan(gateway=b)
    assert [(c.task, c.prompt) for c in a.calls] == [(c.task, c.prompt) for c in b.calls]
    from app.services.model_gateway import default_library

    lib = default_library()
    assert [json.dumps(e, sort_keys=True) for e in lib.examples_for("rule")] == [json.dumps(e, sort_keys=True) for e in default_library().examples_for("rule")]


def test_the_live_comparison_reports_differences_against_a_recorded_variance():
    f = lambda check, target, verdict="true_positive": {"rule_id": check, "target": target, "param": "q", "verdict": verdict}  # noqa: E731
    same = determinism.compare_runs([f("dast-sqli", "GET /a/1")], [f("dast-sqli", "GET /a/2")])
    assert same["variance"] == 0.0 and same["ok"]  # ids in a path do not count as a difference
    drift = determinism.compare_runs([f("dast-sqli", "GET /a"), f("dast-xss", "GET /b")], [f("dast-sqli", "GET /a"), f("dast-xss", "GET /b", "unverified")])
    assert drift["variance"] == pytest.approx(2 / 3, abs=1e-3) and not drift["ok"] and len(drift["only_in_first"]) == 1
    assert determinism.compare_runs([], [])["ok"] and determinism.ALLOWED_VARIANCE == 0.10


@pytest.mark.live
def test_live_two_scans_of_a_practice_target_stay_within_the_allowed_variance():
    import os

    from tools.dast_harness import runner

    token = os.environ.get("SAST_API_TOKEN")
    if not token:
        pytest.skip("set SAST_API_TOKEN and start the practice targets and the backend")
    first = runner.run("dvwa", backend=os.environ.get("SAST_API_URL", "http://127.0.0.1:8000"), token=token)
    second = runner.run("dvwa", backend=os.environ.get("SAST_API_URL", "http://127.0.0.1:8000"), token=token)
    as_findings = lambda r: [{"rule_id": x.split(" ")[0], "target": " ".join(x.split(" ")[1:3]), "param": None, "verdict": "true_positive"} for x in r["true_positives"] + r["false_positives"]]  # noqa: E731
    report = determinism.compare_runs(as_findings(first), as_findings(second))
    print("verdict differences between the two live runs:", report)
    assert report["ok"], report


# ---- offline guarantees -----------------------------------------------------------------------------------------

BLOCKED_MODULES = ("playwright", "anthropic", "openai", "boto3", "botocore", "langchain_ollama", "ollama")


@pytest.fixture()
def sealed(monkeypatch):
    """Sockets, subprocesses and the browser and provider SDKs are all unavailable inside this block."""
    attempts: list[str] = []

    def refuse(name):
        def blocked(*args, **kwargs):
            attempts.append(name)
            raise AssertionError(f"offline test attempted {name}")

        return blocked

    for name in ("connect", "connect_ex"):
        monkeypatch.setattr(socket.socket, name, refuse(f"socket.{name}"))
    monkeypatch.setattr(socket, "create_connection", refuse("socket.create_connection"))
    monkeypatch.setattr(socket, "getaddrinfo", refuse("socket.getaddrinfo"))
    monkeypatch.setattr(subprocess, "Popen", refuse("subprocess.Popen"))
    monkeypatch.setattr("os.system", refuse("os.system"))
    real_import = builtins.__import__

    def guarded(name, *args, **kwargs):
        if name.split(".")[0] in BLOCKED_MODULES:
            attempts.append(f"import {name}")
            raise ImportError(f"{name} is blocked in the offline test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded)
    for name in list(sys.modules):
        if name.split(".")[0] in BLOCKED_MODULES:
            monkeypatch.setitem(sys.modules, name, None)
    yield attempts


def test_the_full_fake_target_pipeline_runs_with_everything_external_blocked(sealed):
    discovery, harness = scan(parallelism=2)
    assert discovery["connection_ok"] and len(harness.written) >= 3 and not sealed
    assert any(r["verdict"] == "true_positive" for _, rows in harness.written for r in rows)


def test_the_mock_engine_scan_through_the_api_runs_with_everything_external_blocked(sealed, tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    monkeypatch.setattr(settings, "use_mock_engine", True)
    monkeypatch.setattr(settings, "scan_logs_dir", str(tmp_path / "logs"))
    app_db.init_db(f"sqlite:///{(tmp_path / 'o.db').as_posix()}")
    client = TestClient(app, headers={"Authorization": f"Bearer {settings.sast_api_token}"})
    project = client.post("/projects", json={"name": "offline", "default_git_url": ""}).json()["id"]
    response = client.post("/scans", json={"project_id": project, "scan_type": "dast", "dast": {"target_url": "http://localhost:3000", "authorized": True}})
    assert response.status_code == 202 and client.get(f"/scans/{response.json()['scan_id']}/status").json()["status"] == "success"
    assert client.get(f"/scans/{response.json()['scan_id']}/export.pdf").status_code == 200 and not sealed


def test_the_seal_actually_blocks_what_it_claims_to(sealed):
    with pytest.raises(AssertionError):
        socket.create_connection(("127.0.0.1", 9))
    with pytest.raises(AssertionError):
        subprocess.Popen(["true"])
    with pytest.raises(ImportError):
        importlib.import_module("playwright.sync_api")
    with pytest.raises(ImportError):
        import anthropic  # noqa: F401
    assert len(sealed) >= 3


# ---- the invariant: a true positive has a detector signal ----------------------------------------------------------

PAGES = [
    (200, "ok", "application/json"), (200, "<p>hello</p>", "text/html"), (500, "You have an error in your SQL syntax", "text/html"),
    (500, "Traceback (most recent call last):\n  File x", "text/plain"), (200, "", "application/json"), (403, "forbidden", "application/json"),
    (200, "root:x:0:0:root:/root:/bin/bash", "text/plain"), (404, "not found", "text/plain"),
]


def random_scenario(rng: random.Random):
    target = FakeTarget()
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        status, body, ctype = rng.choice(PAGES)
        q = request.url.params.get("q", "")
        if q and rng.random() < 0.4:
            body = f"<p>{q}</p>"  # sometimes reflect the input verbatim
            ctype = "text/html"
        return httpx.Response(status, text=body, headers={"content-type": ctype})

    target.route("GET", "/api/x", handler)
    gateway = FakeModelGateway(strict=False)
    check = rng.choice(["dast-sqli", "dast-xss", "dast-cmdi", "dast-info-disclosure", "dast-robustness", "dast-input-validation"])
    value = rng.choice(["1'", "<b>x</b>", "a;id", "{{7*7}}", "' OR '1'='1", "zzz"])
    gateway.script("construct", {"tests": [{"check_id": check, "parameter": "q", "location": "query", "input": value, "expected_signal": "anything"}]})
    advice = rng.choice([{"verdict": "FAIL"}, {"verdict": "PASS"}, {"verdict": "INCONCLUSIVE"}, {"verdict": "fail", "finding": "x"}, {"verdict": "banana"}, {}])
    gateway.script("rule", advice)
    return target, gateway


def test_finding_rows_are_true_positive_or_false_positive_and_a_signal_raises_pass():
    rng = random.Random(20261007)
    confirmed = 0
    for _ in range(250):
        target, gateway = random_scenario(rng)
        harness = Harness(target, build_identities([]), gateway=gateway, rule_set=None)
        runtime = harness.runtime
        store = SessionStore(list(runtime.identities))
        checks = active.loop_checks(resolve_effective_rule_set(CATALOG))
        steps = active.DefaultSteps(gateway=gateway, executor=runtime.executor, store=store, identity_id=store.usable()[0].spec.identity_id, gate=InputGate(), checks=checks)
        outcome = active.run_target(observed("GET", f"{BASE}/api/x?q=1", kind="api"), steps, max_tests=3, log=lambda *_: None)
        for row in active.finding_rows(outcome, checks):
            finding = finding_from_row(row)
            # A model FAIL with no proving signal is stored unverified rather than dropped or
            # auto-confirmed; a proving signal always confirms true_positive.
            assert finding.verdict.value in ("true_positive", "unverified", "false_positive")
            if row["verdict"] == "true_positive":
                confirmed += 1
                proving = set(checks[row["rule_id"]].check.detector_signals)
                names = {s["name"] for s in row["evidence"]["signals"]}
                assert names <= proving and proving <= signal_names()
        for record in outcome.records:
            if record.outcome is None:
                continue
            if record.outcome.overridden:
                assert record.outcome.verdict is CheckVerdict.FAIL and record.outcome.signals
    assert confirmed > 10


def test_every_row_the_other_stages_write_obeys_the_same_rule():
    _, harness = scan()
    rows = [r for _, batch in harness.written for r in batch]
    assert rows
    for row in rows:
        finding_from_row(row)
        if row["verdict"] == "true_positive" and row["rule_id"] != "dast-api-inventory":
            assert row["evidence"]["signals"] or row["verdict_reason"], row["rule_id"]
