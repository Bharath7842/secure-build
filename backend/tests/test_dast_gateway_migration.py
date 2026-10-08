"""DAST-02-020: every existing model call site goes through the gateway with its own task name,
keeps its prompt and its deterministic fallback, and produces the same result as before."""

from __future__ import annotations

import json
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.config import settings
from app.dast import api_analysis
from app.dast.domain.interfaces import ModelReply
from app.dast.domain.inventory import observed
from app.dast.nodes import classify_login_type as classify
from app.dast.nodes import crawl, login
from app.services import dast_narration, engine_adapter

pytestmark = pytest.mark.unit

FALLBACK = ModelReply(data={}, fallback_used=True)


def page_mock(url="http://t.test/login"):
    page = MagicMock()
    page.url = url
    page.eval_on_selector_all.return_value = []
    page.inner_text.return_value = ""
    return page


# ---- login classification (task: fingerprint) -------------------------------------------------


def classify_state(gateway, page=None):
    return {"gateway": gateway, "page": page or page_mock(), "login_url": "http://t.test/login", "verbose": False}


def test_login_classification_treats_a_visible_password_form_as_simple_when_the_model_is_unsure(fake_gateway):
    page = page_mock()
    page.eval_on_selector_all.return_value = [
        {"inputs": [{"name": "email", "type": "text", "id": "email"}, {"name": "password", "type": "password", "id": "password"}], "buttons": ["Log in"]}
    ]
    fake_gateway.script("fingerprint", {"login_type": "unknown", "reason": "cookie banner in the way"})
    state = classify.classify_login_type(classify_state(fake_gateway, page))
    assert state["login_type"] == "simple_form"


def test_login_classification_uses_the_fingerprint_task(fake_gateway):
    fake_gateway.script("fingerprint", {"login_type": "simple_form", "reason": "one page"})
    state = classify.classify_login_type(classify_state(fake_gateway))
    assert state["login_type"] == "simple_form" and state["login_type_reason"] == "one page"
    (call,) = fake_gateway.calls
    assert call.task == "fingerprint" and "Classify the login into EXACTLY one" in call.prompt
    assert call.reply_schema["properties"]["login_type"]["enum"] == sorted(classify.LOGIN_TYPES)


@pytest.mark.parametrize("reply", [FALLBACK, {"login_type": "telepathy"}])
def test_login_classification_falls_back_to_unknown(fake_gateway, reply):
    fake_gateway.script("fingerprint", reply)
    state = classify.classify_login_type(classify_state(fake_gateway))
    assert state["login_type"] == "unknown" and state["login_type_reason"] == "LLM classification failed"
    assert state["stop_reason"] == "unknown_not_supported"


# ---- login steps (task: login_selectors) ------------------------------------------------------


def login_state(gateway, page):
    return {
        "gateway": gateway, "page": page, "login_url": "http://t.test/login", "username": "alice", "password": "pw-secret",
        "verbose": False, "login_error": "", "login_success": False,
    }


@pytest.fixture(autouse=True)
def _no_dom(monkeypatch):
    monkeypatch.setattr(login, "extract_interactive_elements", lambda page: "[]")


def test_agentic_login_asks_the_login_selectors_task_each_step(fake_gateway):
    page = page_mock()
    # No matching username/submit shortcut (count 0) so the model still drives the steps;
    # password locators report 1 so looks_logged_in stays false.
    page.locator.return_value.count.return_value = 0
    page.locator.return_value.is_visible.return_value = False
    fake_gateway.script("login_selectors", {"action_type": "fill_username", "selector": "#email", "reason": "email field"})
    fake_gateway.script("login_selectors", {"action_type": "give_up", "selector": None, "reason": "stuck"})
    state = login.login(login_state(fake_gateway, page))
    assert [c.task for c in fake_gateway.calls] == ["login_selectors", "login_selectors"]
    page.fill.assert_any_call("#email", "alice", timeout=5000)
    assert state["login_success"] is False and state["login_error"] == "stuck"
    assert "pw-secret" not in fake_gateway.calls[0].prompt  # the password never reaches the model


def test_give_up_after_leaving_the_login_hash_is_treated_as_success(fake_gateway):
    """Juice Shop lands on `#/search` after a good submit. The model then says 'not a login form'
    because it is looking at the product list — that is success, not a failed login."""
    page = page_mock("http://127.0.0.1:3001/#/search")
    page.locator.return_value.count.return_value = 0
    page.locator.return_value.is_visible.return_value = False
    fake_gateway.script("login_selectors", {"action_type": "give_up", "selector": None, "reason": "Login completed. Current page is search/product view."})
    state = login.login(login_state(fake_gateway, page) | {"login_url": "http://127.0.0.1:3001/#/login"})
    assert state["login_success"] is True
    assert state["crawl_start_url"] == "http://127.0.0.1:3001/#/search"


def test_login_falls_back_to_the_hardcoded_selector_list_when_the_gateway_fails(fake_gateway):
    page = page_mock()
    # The form's fields exist; after the submit click the password field is gone and the URL moved on.
    page.locator.side_effect = lambda selector: MagicMock(count=lambda: 0 if "password" in selector and page.url != "http://t.test/login" else 1)
    page.click.side_effect = lambda *a, **k: setattr(page, "url", "http://t.test/home")
    fake_gateway.script("login_selectors", FALLBACK)
    state = login.login(login_state(fake_gateway, page))
    assert state["selector_source"] == "fallback" and state["login_success"] is True
    assert state["identified_username_selector"] == login.FALLBACK_USERNAME_SELECTORS[0]
    assert state["identified_password_selector"] == login.FALLBACK_PASSWORD_SELECTOR
    assert state["identified_submit_selector"] == login.FALLBACK_SUBMIT_SELECTORS[0]


# ---- crawl planning (task: crawl_plan) --------------------------------------------------------


def crawl_state(gateway, urls=("http://t.test/a", "http://t.test/admin")):
    return {
        "gateway": gateway, "verbose": False, "pages_data": [], "max_pages": 10, "max_depth": 3, "max_runtime_minutes": 10,
        "crawl_start_time": time.time(), "consecutive_low_value_visits": 0, "visited": set(), "api_calls": [],
        "skipped_duplicate_patterns": [], "warnings": [], "noise_params": [], "crawl_stop_reason": "",
        "queue": [{"url": u, "depth": 1, "pattern": u} for u in urls],
    }


def test_crawl_planner_chooses_a_queued_url(fake_gateway):
    fake_gateway.script("crawl_plan", {"action": "choose_next_url", "url": "http://t.test/admin", "reason": "admin panel"})
    state = crawl_state(fake_gateway)
    item = crawl.plan_next_url(state)
    assert item["url"] == "http://t.test/admin" and item["reason"] == "admin panel"
    assert [q["url"] for q in state["queue"]] == ["http://t.test/a"]
    assert fake_gateway.calls[0].task == "crawl_plan" and "EXACTLY matches one currently in the queue" in fake_gateway.calls[0].prompt


def test_crawl_planner_stop_and_fallbacks(fake_gateway):
    fake_gateway.script("crawl_plan", {"action": "stop_crawl", "stop_reason": "diminishing_returns", "details": "nothing new"})
    state = crawl_state(fake_gateway)
    assert crawl.plan_next_url(state) is None and state["crawl_stop_reason"] == "diminishing_returns"

    fake_gateway.script("crawl_plan", {"action": "choose_next_url", "url": "http://elsewhere.test/x", "reason": "r"})
    state = crawl_state(fake_gateway)
    item = crawl.plan_next_url(state)
    assert item["url"] == "http://t.test/a" and state["warnings"][0]["event"] == "hallucinated_url"

    fake_gateway.script("crawl_plan", FALLBACK)
    state = crawl_state(fake_gateway)
    item = crawl.plan_next_url(state)
    assert item["url"] == "http://t.test/a" and "FIFO" in item["reason"] and state["warnings"][0]["event"] == "llm_call_failed"


# ---- active testing (tasks: construct, rule) -------------------------------------------------

TARGET = observed("GET", "http://t.test/api/products?id=1", kind="api")


def loop_steps(gateway):
    from app.dast import active
    from app.dast.domain.ruleset import resolve_effective_rule_set
    from app.dast.input_gate import InputGate
    from app.services.dast_catalog import default_catalog

    context = MagicMock()
    steps = active.DefaultSteps(
        gateway=gateway, executor=context, store=MagicMock(), identity_id="x", gate=InputGate(),
        checks=active.loop_checks(resolve_effective_rule_set(default_catalog())),
    )
    return steps, context


def test_construct_uses_the_construct_task_and_lists_only_the_enabled_checks(fake_gateway):
    fake_gateway.script("construct", {"tests": [{"check_id": "dast-sqli", "parameter": "id", "location": "query", "input": "'", "expected_signal": "sql error"}]})
    steps, _ = loop_steps(fake_gateway)
    construction = steps.construct(TARGET)
    assert [p.check_id for p in construction.proposals] == ["dast-sqli"] and not construction.failed
    call = fake_gateway.calls[0]
    assert call.task == "construct" and "Available checks" in call.prompt and "dast-sqli" in call.prompt and "untrusted data" in call.prompt
    assert "dast-bola" not in call.prompt and "dast-passive-missing-csp" not in call.prompt  # not loop checks


def test_construct_and_rule_report_a_model_that_could_not_help(fake_gateway):
    fake_gateway.script("construct", FALLBACK)
    steps, _ = loop_steps(fake_gateway)
    assert steps.construct(TARGET).failed
    fake_gateway.script("rule", FALLBACK)
    from app.dast.domain.active import Exchange
    from app.dast.domain.validation import ValidatedTest  # noqa: F401
    test = steps.gate.validate(method="GET", check_id="dast-sqli", parameter="id", location="query", value="'")
    assert steps.rule(TARGET, test, Exchange(200, 2, "ok"), Exchange(500, 2, "no"), []) is None


def test_the_rule_task_gets_the_detector_signals_and_the_reply_is_only_advice(fake_gateway):
    from app.dast.domain.active import Exchange
    from app.dast.domain.entities import CheckVerdict, DetectorSignal

    fake_gateway.script("rule", {"verdict": "fail", "finding": "db error", "severity": "high", "confidence": "high", "evidence": "500"})
    steps, _ = loop_steps(fake_gateway)
    test = steps.gate.validate(method="GET", check_id="dast-sqli", parameter="id", location="query", value="'")
    advice = steps.rule(TARGET, test, Exchange(200, 2, "ok"), Exchange(500, 20, "SQL syntax error"), [DetectorSignal("db_error_surfaced", "SQL syntax")])
    assert advice.verdict is CheckVerdict.FAIL and advice.severity == "HIGH" and advice.finding == "db error"
    call = fake_gateway.calls[0]
    assert call.task == "rule" and "db_error_surfaced" in call.prompt and "SQL syntax error" in call.prompt


def test_a_test_the_guard_refused_is_not_reported_as_a_finding():
    result = {
        "label": "POST /api/x", "url": "http://t/api/x",
        "checks": [{"check_id": "dast-sqli", "check": "SQL Injection", "cwe": "CWE-89", "owasp_category": "A03:2021-Injection", "target": "id",
                    "location": "body", "payload": "'", "severity": "MEDIUM", "verdict": "INCONCLUSIVE", "confidence": "LOW", "finding": "", "evidence": "",
                    "response": {"status_code": None, "error": "request not sent: method_not_permitted"}}],
    }
    assert api_analysis.finding_rows_from_analysis(result) == []


def test_an_oversized_input_is_discarded_and_the_prompt_asks_for_short_ones(fake_gateway):
    fake_gateway.script("construct", {"tests": [
        {"check_id": "dast-robustness", "parameter": "q", "location": "query", "input": "a" * 5000, "expected_signal": "5xx"},
        {"check_id": "dast-sqli", "parameter": "q", "location": "query", "input": "1'", "expected_signal": "sql error"},
    ]})
    steps, _ = loop_steps(fake_gateway)
    construction = steps.construct(TARGET)
    assert [p.check_id for p in construction.proposals] == ["dast-sqli"] and construction.malformed == 1
    assert "at most 80 characters" in fake_gateway.calls[0].prompt


# ---- narration (task: narrate) ----------------------------------------------------------------


@pytest.fixture()
def narration_gateway(monkeypatch, fake_gateway):
    monkeypatch.setattr(dast_narration, "_gateway", fake_gateway)
    return fake_gateway


def test_narration_uses_the_narrate_task_and_parses_the_reply(narration_gateway):
    narration_gateway.script("narrate", {"narration": "I found 3 pages.", "reasoning": ["forms matter"]})
    assert dast_narration._call_llm("evidence") == {"narration": "I found 3 pages.", "reasoning": ["forms matter"]}
    call = narration_gateway.calls[0]
    assert call.task == "narrate" and call.prompt == "evidence" and call.max_tokens == 600
    # Narration is the one task that asks for extended thinking (Bedrock's path to it) —
    # a no-op for providers that don't support it, but required for Bedrock to show any.
    assert call.thinking is True


def test_narration_falls_back_to_the_template_when_the_model_does_not_help(narration_gateway):
    narration_gateway.script("narrate", FALLBACK)
    assert dast_narration._call_llm("evidence") is None
    narration_gateway.script_failure("narrate")
    assert dast_narration._call_llm("evidence") is None


def test_narration_stream_goes_through_the_gateway(monkeypatch):
    class Streamer:
        def stream(self, task, system, prompt, **kw):
            assert task == "narrate"
            assert kw.get("thinking") is True
            yield "thinking", "hmm"
            yield "response", '{"narration": "ok"}'
            yield "done", ""

    monkeypatch.setattr(dast_narration, "_gateway", Streamer())
    assert list(dast_narration.stream_llm("u")) == [("thinking", "hmm"), ("response", '{"narration": "ok"}'), ("done", "")]


# ---- the live path builds the gateway from the scan's snapshot --------------------------------


def test_live_engine_path_routes_models_from_the_scan_snapshot(monkeypatch, fake_gateway):
    monkeypatch.setenv("USE_MOCK_ENGINE", "false")
    monkeypatch.setattr(settings, "use_mock_engine", False)
    monkeypatch.setattr(settings, "run_dast", True)
    seen = {}

    def fake_run(**kwargs):
        seen.update(kwargs)
        return {"discovery": {"pages": []}}

    monkeypatch.setattr("app.dast.runner.run_dast_scan", fake_run)
    built = {}

    def fake_build(routing=None, **kw):
        built["routing"] = routing
        fake_gateway.usage = SimpleNamespace(summary=lambda: {"call_count": 4})
        return fake_gateway

    monkeypatch.setattr("app.services.model_gateway.build_gateway", fake_build)
    snapshot = {**settings.dast_effective_settings(), "model_routing": {"rule": ["anthropic", "claude-x"], "construct": ["ollama", "m"]}, "max_pages": 7}
    result = engine_adapter.run_dast_scan(
        project=None, dast_input={"target_url": "http://t.test", "max_pages": 0}, effective_settings=snapshot
    )
    assert built["routing"] == {"rule": ("anthropic", "claude-x"), "construct": ("ollama", "m")}
    runtime = seen["runtime"]
    assert runtime.gateway is fake_gateway and runtime.effective["max_pages"] == 7 and runtime.target_url == "http://t.test"
    assert result["usage_summary"] == {"call_count": 4}
    assert set(seen) == {"runtime", "discovery_writer", "findings_writer", "should_abort"}  # the engine takes no model client


def test_no_engine_module_builds_a_model_client_itself():
    """The old direct callers are gone: no ChatOllama anywhere in the engine sources."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "app" / "dast"
    offenders = [str(p.relative_to(root)) for p in root.rglob("*.py") if "ChatOllama" in p.read_text()]
    assert offenders == []


def test_a_test_the_guard_refused_is_not_reported_as_a_finding():
    result = {
        "label": "POST /api/x", "url": "http://t/api/x",
        "checks": [{"check_id": "dast-sqli", "check": "SQL Injection", "cwe": "CWE-89", "owasp_category": "A03:2021-Injection", "target": "id",
                    "location": "body", "payload": "'", "severity": "MEDIUM", "verdict": "INCONCLUSIVE", "confidence": "LOW", "finding": "", "evidence": "",
                    "response": {"status_code": None, "error": "request not sent: method_not_permitted"}}],
    }
    assert api_analysis.finding_rows_from_analysis(result) == []
