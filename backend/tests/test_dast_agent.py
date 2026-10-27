"""Planner validation, bounded histories and the adaptive loop over the real guarded fake target."""

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from app.dast.active import run_target_agentic
from app.dast.domain.agent import AgentBudget, History, Hypothesis, MAX_HISTORY_TURNS, Turn, agent_limits, parse_plan, should_stop, target_key
from app.dast.domain.entities import FindingVerdict
from tests.dast_fixtures import FakeModelGateway
from tests.test_dast_active import SEARCH, SQLI, ep, harness_steps, rule_set, script_construct, search_target
from tests.test_dast_engine import Harness, identities


def hypothesis(**changes):
    return replace(Hypothesis("h1", target_key(SEARCH), "A03:2021", ("dast-sqli",), "Check the search parameter", 1, 4), **changes)


def raw(**changes):
    return {"target_key": target_key(SEARCH), "owasp": "A03:2021", "check_ids": ["dast-sqli"], "priority": 3, "max_turns": 4, **changes}


def test_plan_rejects_invented_work_dedupes_ranks_and_caps():
    reply = {"hypotheses": [raw(), raw(), raw(target_key="GET /invented"), raw(check_ids=["invented"]),
                             "bad", raw(priority="first"), raw(owasp="invented"),
                             raw(check_ids=["dast-xss"], priority=1)]}
    plan = parse_plan(reply, [SEARCH], {"dast-sqli": 1, "dast-xss": 1}, max_hypotheses=1)
    assert [h.check_ids for h in plan.hypotheses] == [("dast-xss",)]
    assert plan.dropped == {"malformed": 3, "unknown_endpoint": 1, "unknown_check": 1, "duplicate": 1, "over_cap": 1}
    assert parse_plan({"hypotheses": {}}, [SEARCH], {}, max_hypotheses=3).hypotheses == ()
    assert parse_plan(None, [SEARCH], {}, max_hypotheses=3).hypotheses == ()


def test_history_is_bounded_but_remembers_proof_after_eviction():
    h = hypothesis()
    history = History(h)
    history.append(Turn(signals=("db_error_surfaced",), proven=True))
    for _ in range(MAX_HISTORY_TURNS + 5):
        history.append(Turn(status=200))
    assert len(history.turns) == MAX_HISTORY_TURNS
    assert should_stop(history, h, AgentBudget())


@pytest.mark.parametrize("reason", ["model_stopped", "cancelled", "attempts", "budget", "hypothesis_budget"])
def test_every_stop_condition(reason):
    h, budget = hypothesis(), AgentBudget(10, 4)
    history = History(h)
    assert not should_stop(history, h, budget)
    if reason == "budget":
        budget = AgentBudget(0)
    elif reason == "hypothesis_budget":
        for _ in range(4):
            assert budget.reserve(h)
    else:
        setattr(history, reason, 4 if reason == "attempts" else True)
    assert should_stop(history, h, budget)


def test_scan_budget_is_atomic_across_workers_and_caps_each_hypothesis():
    budget = AgentBudget(17, 3)
    hs = [hypothesis(id=f"h{i}") for i in range(20)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        admitted = list(pool.map(lambda h: budget.reserve(h), hs * 10))
    assert sum(admitted) == 17 and budget.remaining() == 0
    assert all(budget.used_by(h) <= 3 for h in hs)


def test_small_local_models_have_lower_turn_limits():
    assert agent_limits(60, 4, {"construct": ["ollama", "gpt-oss:20b"]}) == (20, 2)
    assert agent_limits(60, 4, {"construct": ["ollama", "model:70b"]}) == (60, 4)
    for provider in ("claude_cli", "anthropic", "bedrock", "openai"):
        assert agent_limits(60, 4, {"construct": [provider, "model"]}) == (60, 4)


def test_adapts_to_compact_outcomes_and_stops_on_detector_proof():
    gateway = FakeModelGateway(strict=False)
    script_construct(gateway, {**SQLI, "input": "shoes"})
    script_construct(gateway, SQLI)
    script_construct(gateway, SQLI)  # must not reach this one
    steps, harness = harness_steps(search_target(), gateway)
    try:
        budget = AgentBudget(10, 4)
        outcome = run_target_agentic(SEARCH, steps, hypothesis(), budget, max_tests=5)
        assert len(outcome.records) == 2 and budget.remaining() == 8
        assert outcome.records[-1].outcome.finding_verdict is FindingVerdict.TRUE_POSITIVE
        calls = [c for c in gateway.calls if c.task == "construct"]
        assert len(calls) == 2 and '"status": 200' in calls[1].prompt
        assert "previous_probes" in calls[1].prompt and "results" not in calls[1].prompt
    finally:
        harness.runtime.close()


@pytest.mark.parametrize("total,per,expected", [(20, 2, 2), (1, 4, 1), (20, 4, 4)])
def test_turn_caps_are_respected(total, per, expected):
    gateway = FakeModelGateway(strict=False)
    gateway.script("construct", {"tests": [{**SQLI, "input": "harmless"}]}, repeat=10)
    steps, harness = harness_steps(search_target(), gateway)
    try:
        run_target_agentic(SEARCH, steps, hypothesis(), AgentBudget(total, per), max_tests=1)
        assert len([c for c in gateway.calls if c.task == "construct"]) == expected
    finally:
        harness.runtime.close()


def test_empty_reply_stops_and_safe_mode_and_cancellation_make_no_model_call():
    gateway = FakeModelGateway(strict=False)
    gateway.script("construct", {"tests": []})
    steps, harness = harness_steps(search_target(), gateway)
    try:
        assert run_target_agentic(SEARCH, steps, hypothesis(), AgentBudget(), max_tests=2).skipped == "no applicable tests"
        gateway.calls.clear()
        assert run_target_agentic(ep("POST"), steps, hypothesis(), AgentBudget(), max_tests=2).skipped == "not tested: safe mode"
        assert run_target_agentic(SEARCH, steps, hypothesis(), AgentBudget(), max_tests=2, cancelled=lambda: True).skipped == "cancelled"
        assert not gateway.calls
    finally:
        harness.runtime.close()


def test_rejected_followup_still_passes_input_gate_and_secrets_are_redacted():
    gateway = FakeModelGateway(strict=False)
    script_construct(gateway, {**SQLI, "input": "shoes"})
    script_construct(gateway, {**SQLI, "input": "DROP TABLE users"})
    steps, harness = harness_steps(search_target(), gateway)
    steps.secrets = lambda: ("private-credential-value",)
    try:
        outcome = run_target_agentic(SEARCH, steps, hypothesis(rationale="private-credential-value"), AgentBudget(), max_tests=2)
        assert outcome.dropped_unsafe == 1 and len(outcome.records) == 1
        assert all("private-credential-value" not in c.prompt for c in gateway.calls)
        assert not any("DROP" in str(r.url) for r in harness.target.requests)
    finally:
        harness.runtime.close()


def test_failed_followup_keeps_completed_results():
    gateway = FakeModelGateway(strict=False)
    script_construct(gateway, {**SQLI, "input": "shoes"})
    gateway.script_failure("construct", RuntimeError("private-provider-detail"))
    steps, harness = harness_steps(search_target(), gateway)
    messages = []
    try:
        outcome = run_target_agentic(SEARCH, steps, hypothesis(), AgentBudget(), max_tests=2, log=messages.append)
        assert len(outcome.records) == 1 and not outcome.error
        assert any("retaining completed tests" in m for m in messages)
        assert not any("private-provider-detail" in m for m in messages)
    finally:
        harness.runtime.close()


def test_construct_masks_credentials_before_truncating_samples():
    from app.dast.domain.entities import Location, Parameter
    secret = "private-credential-" * 20
    endpoint = replace(SEARCH, parameters=(Parameter("value", Location.QUERY, (secret,)),), body_sample=json.dumps({"password": secret}))
    gateway = FakeModelGateway(strict=False)
    gateway.script("construct", {"tests": []})
    steps, harness = harness_steps(search_target(), gateway)
    steps.secrets = lambda: (secret,)
    try:
        steps.construct(endpoint, history=History(hypothesis()))
        assert "private-credential-" not in gateway.calls_for("construct")[0].prompt
    finally:
        harness.runtime.close()


def test_planner_exception_is_an_empty_plan():
    from types import SimpleNamespace
    from app.dast.nodes.plan_tests import plan_tests
    gateway = FakeModelGateway(strict=False)
    gateway.script_failure("plan", RuntimeError("private-provider-detail"))
    steps, harness = harness_steps(search_target(), gateway)
    harness.runtime.rule_set = rule_set()
    state = {"runtime": harness.runtime, "gateway": gateway, "agent_mode": True,
             "inventory": SimpleNamespace(endpoints=lambda: [SEARCH])}
    try:
        plan_tests(state)
        assert not state["test_plan"].hypotheses and state["agent_budget"] is None
    finally:
        harness.runtime.close()


def _engine(agent_mode, plan_reply):
    target = search_target()
    target.set_openapi({"openapi": "3.0.0", "paths": {"/api/search": {"get": {"parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}]}}}})
    gateway = FakeModelGateway(strict=False)
    if plan_reply is not None:
        gateway.script("plan", plan_reply)
    gateway.script("construct", {"tests": [SQLI]}, repeat=10)
    harness = Harness(target, identities(), gateway=gateway, request={"agent_mode": agent_mode, "max_targets": 1, "max_agent_turns": 4})
    from tests.test_dast_engine import default_rule_set
    from app.dast.domain.ruleset import effective_from_dict
    harness.runtime.rule_set = effective_from_dict(default_rule_set())
    discovery = harness.run(run_analysis=True)
    return discovery, harness, gateway


@pytest.mark.parametrize("reply", [None, {"hypotheses": []}, {"hypotheses": [raw(target_key="GET /invented")]}])
def test_empty_or_failed_planning_keeps_findings_byte_identical(reply):
    off, original, off_gateway = _engine(False, None)
    fallback, current, gateway = _engine(True, reply)
    assert not [c for c in off_gateway.calls if c.task == "plan"]
    assert len([c for c in gateway.calls if c.task == "plan"]) == 1
    assert json.dumps(original.written, sort_keys=True) == json.dumps(current.written, sort_keys=True)
    assert off["api_analysis"] == fallback["api_analysis"]


def test_engine_runs_one_planner_and_enforces_proof_stop(capsys):
    discovery, harness, gateway = _engine(True, {"hypotheses": [raw()]})
    assert len([c for c in gateway.calls if c.task == "plan"]) == 1
    assert len([c for c in gateway.calls if c.task == "construct"]) == 1
    assert discovery["active_testing"]["agent"]["turns"] == 1
    assert "### DAST: planning tests" in capsys.readouterr().out
