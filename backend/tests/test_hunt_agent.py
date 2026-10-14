"""Agentic hunt end to end with a scripted LLM: planner, investigator loop
(search outcomes, INSUFFICIENT_EVIDENCE, strategy switching, loop guards),
validator (grounding, evidence levels, verdict caps, dedupe) and the engine.

Fully offline. Needs rg; the graph-resolved (L2) paths also need
tree-sitter-java and skip without it.
"""

import json
import re
import sys
import threading
from pathlib import Path

import pytest

pytest.importorskip("boto3", reason="pipeline modules import llm_client")

_ENGINE_DIR = Path(__file__).resolve().parents[1] / "sast_engine"
if str(_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(_ENGINE_DIR))

from pipeline.hunt import engine as hunt_engine  # noqa: E402
from pipeline.hunt.budget import BudgetLimits, HuntBudget  # noqa: E402
from pipeline.hunt.evidence import EvidenceLedger  # noqa: E402
from pipeline.hunt.investigator import (  # noqa: E402
    OUTCOME_INSUFFICIENT,
    SINK_SEARCH,
    SOURCE_TRACE,
    STATUS_BUDGET,
    STATUS_INCONCLUSIVE,
    STATUS_REPORTED,
    Investigator,
)
from pipeline.hunt.llm import BudgetedLlm  # noqa: E402
from pipeline.hunt.planner import Hypothesis  # noqa: E402
from pipeline.hunt.prompts import HUNT_SYSTEM  # noqa: E402
from pipeline.hunt.rg_runner import RgRunner, find_rg_binary  # noqa: E402
from pipeline.hunt.symbols import SymbolService  # noqa: E402
from pipeline.hunt.tools import HuntToolbox  # noqa: E402
from pipeline.hunt.validator import (  # noqa: E402
    STATUS_CORROBORATED,
    STATUS_HALLUCINATED,
    STATUS_PUBLISHED,
    ExistingFindings,
    Validator,
)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "hunt_java"
INVENTORY = sorted(str(p.relative_to(FIXTURE)) for p in FIXTURE.rglob("*.java"))
CONTROLLER = "src/main/java/com/acme/web/OrderController.java"
SERVICE = "src/main/java/com/acme/service/OrderService.java"
DAO = "src/main/java/com/acme/repo/OrderDao.java"
SECURITY = "src/main/java/com/acme/security/SecurityConfig.java"
RISK = {CONTROLLER: "CRITICAL", SERVICE: "HIGH", DAO: "MEDIUM",
        "src/main/java/com/acme/util/Paging.java": "LOW", SECURITY: "CRITICAL"}
DAO_SINK_LINE = '            return st.executeQuery("SELECT * FROM orders WHERE name = \'" + name + "\'");'

pytestmark = pytest.mark.skipif(find_rg_binary() is None, reason="ripgrep (rg) is not installed")


def _has_tree_sitter() -> bool:
    try:
        import tree_sitter_java  # noqa: F401
    except ImportError:
        return False
    return True


needs_graph = pytest.mark.skipif(not _has_tree_sitter(), reason="tree-sitter-java is not installed")


def _graph():
    from pipeline.call_graph import build_call_graph

    return build_call_graph(FIXTURE, INVENTORY)


# --- scripted LLM -----------------------------------------------------------


def _verifier_tp(_user):
    return {"findings": [{
        "verdict": "true_positive", "title": "verified", "line": 15, "snippet": "executeQuery",
        "severity": "HIGH", "confidence": 0.9, "cwe": "CWE-89", "verdict_reason": "user input concatenated",
    }]}


class ScriptedLLM:
    """Routes by `step`: planner, investigator turns (per sink kind, from the
    hypothesis header in the prompt), flow verifier and construct confirm."""

    def __init__(self, scripts=None, *, planner=None, verifier=_verifier_tp, construct="true_positive",
                 default=None):
        self.default = default
        self.scripts = {k: list(v) for k, v in (scripts or {}).items()}
        self.planner = planner or {"hypotheses": []}
        self.verifier = verifier
        self.construct = construct
        self.calls = []
        self._lock = threading.Lock()

    def __call__(self, system, user, **kwargs):
        step = kwargs.get("step")
        with self._lock:
            self.calls.append((step, system, user))
        if step == "hunt_plan":
            return json.dumps(self.planner)
        if step == "hunt_verify":
            return json.dumps(self.verifier(user))
        if step == "group_confirm_triage_findings":
            return json.dumps({"decisions": [{"verdict": self.construct, "confidence": 0.9,
                                              "verdict_reason": "scripted construct decision"}]})
        if step == "hunt_investigate":
            kind = re.search(r"sink kind '(\w+)'", user).group(1)
            with self._lock:
                queue = self.scripts.get(kind) or []
                item = queue.pop(0) if queue else None
            if item is None:
                return json.dumps({"thought": "not scripted", "action": "abandon",
                                   "args": {"verdict": "inconclusive", "reason": "not scripted"}})
            return item if isinstance(item, str) else json.dumps(item(user) if callable(item) else item)
        if self.default is not None:
            return self.default
        raise AssertionError(f"unexpected step {step}")

    def steps(self, name):
        return [c for c in self.calls if c[0] == name]


def _sql_hypothesis():
    return Hypothesis(id="S1", cwe="CWE-89", vuln_class="SQL injection", sink_kind="sql",
                      rationale="sql sinks present")


SQL_REPORT = {
    "title": "SQL injection in OrderDao.findByName via search parameter q",
    "cwe": "CWE-89", "severity": "HIGH", "verdict": "true_positive", "confidence": 0.9,
    "source": {"file": CONTROLLER, "line": 23, "expr": '@RequestParam("q") String q'},
    "sink": {"file": DAO, "line": 15, "expr": "st.executeQuery("},
    "path": [{"file": CONTROLLER, "line": 24, "method": "search", "role": "hop"},
             {"file": SERVICE, "line": 16, "method": "search", "role": "hop"}],
    "sanitizers_checked": ["no binding or escaping between controller and DAO"],
    "quoted_lines": [{"file": DAO, "line": 15, "text": DAO_SINK_LINE.strip()}],
    "verdict_reason": "q flows unmodified into a concatenated SQL string.",
    "ai_fix": "Use a PreparedStatement with a bound parameter.",
}


def _sql_script():
    return [
        # 1. look at the sink the engine's pre-run search_sinks surfaced
        {"thought": "DAO concatenates", "strategy": "sink_search", "action": "read",
         "args": {"file": DAO, "start": 12, "end": 20}},
        # 2. premature report: sink only
        {"thought": "looks bad", "action": "report",
         "evidence": {"sink": {"file": DAO, "line": 15, "expr": "st.executeQuery("}},
         "args": {"findings": [{**SQL_REPORT, "source": None, "path": []}]}},
        # 3. tries another sink search — blocked after the refusal
        {"thought": "more sinks", "action": "search_sinks", "args": {"kind": "sql"}},
        # 4-5. switch to source tracing through resolved callers
        {"thought": "who calls it", "strategy": "source_trace", "action": "callers",
         "args": {"method": "findByName", "class_name": "OrderDao"}},
        {"thought": "and upstream", "strategy": "source_trace", "action": "callers",
         "args": {"method": "search", "class_name": "OrderService"}},
        # 6. read the entry point
        {"thought": "entry point", "strategy": "source_trace", "action": "read",
         "args": {"file": CONTROLLER, "start": 22, "end": 25}},
        # 7. sanitizer check, recording the established source and path
        {"thought": "any escaping?", "strategy": "sanitizer_check", "action": "find_sanitizers",
         "args": {"kind": "sql", "file": DAO, "start": 12, "end": 18},
         "evidence": {"source": SQL_REPORT["source"], "path": SQL_REPORT["path"]}},
        # 8. complete report
        {"thought": "complete", "action": "report", "args": {"findings": [SQL_REPORT]}},
    ]


def _parts(graph=None, llm=None, budget=None, **toolbox_kwargs):
    runner = RgRunner(FIXTURE, allowed_files=INVENTORY)
    symbols = SymbolService(FIXTURE, runner, graph=graph)
    budget = budget or HuntBudget(BudgetLimits(max_usd=None), provider="openai_compat", model="m")
    toolbox = HuntToolbox(root=FIXTURE, runner=runner, symbols=symbols, ledger=EvidenceLedger(),
                          risk_by_path=RISK, inventory=INVENTORY, rg_gate=budget.reserve_rg, **toolbox_kwargs)
    budgeted = BudgetedLlm(budget=budget, usage=None, provider="openai_compat", model="m", call_llm_fn=llm) if llm else None
    return runner, symbols, toolbox, budgeted, budget


def _validator(symbols, llm, existing=None):
    vbox = HuntToolbox(root=FIXTURE, runner=symbols.runner, symbols=symbols, ledger=EvidenceLedger(),
                       risk_by_path=RISK, inventory=INVENTORY)
    return Validator(toolbox=vbox, symbols=symbols, existing=existing or ExistingFindings(), llm=llm,
                     stack_context="Java / Spring")


# --- investigator ------------------------------------------------------------


@needs_graph
def test_sink_only_report_is_refused_then_source_is_traced_and_confirmed():
    llm = ScriptedLLM({"sql": _sql_script()})
    _runner, symbols, toolbox, budgeted, _budget = _parts(graph=_graph(), llm=llm)
    result = Investigator(_sql_hypothesis(), toolbox=toolbox, llm=budgeted, max_steps=14).run()

    assert result.status == STATUS_REPORTED
    # The refused sink-only report, then the blocked sink re-search.
    assert result.insufficient_evidence == 2
    assert result.blocked_actions == 1
    trail = result.strategy_trail
    assert trail.index(SOURCE_TRACE) > trail.index(SINK_SEARCH)
    refusal_prompt = llm.steps("hunt_investigate")[2][2]
    assert OUTCOME_INSUFFICIENT in refusal_prompt
    assert "source:" in refusal_prompt and "source_trace" in refusal_prompt
    blocked_prompt = llm.steps("hunt_investigate")[3][2]
    assert "blocked" in blocked_prompt

    outcome = _validator(symbols, BudgetedLlm(budget=_budget, usage=None, provider="openai_compat",
                                              model="m", call_llm_fn=llm)).validate(result.candidates[0], result.ledger)
    assert outcome.status == STATUS_PUBLISHED
    assert outcome.evidence_level == "L2"
    assert outcome.verifier == "agree"
    f = outcome.finding
    assert (f["verdict"], f["file_path"], f["line"], f["kind"]) == ("true_positive", DAO, 15, "hunt")
    assert f["affected_files"] == [CONTROLLER, SERVICE, DAO]
    assert [s["role"] for s in f["flow_path"]] == ["source", "hop", "hop", "sink"]
    assert f["rule_id"] == "hunt-cwe-89"
    # The verifier saw a fresh slice, not the investigator's transcript.
    verify_prompt = llm.steps("hunt_verify")[0][2]
    assert "Evidence established so far" not in verify_prompt


def test_without_a_call_graph_the_same_path_can_only_reach_l1_and_is_never_tp():
    llm = ScriptedLLM({"sql": _sql_script()})
    _runner, symbols, toolbox, budgeted, budget = _parts(graph=None, llm=llm)
    result = Investigator(_sql_hypothesis(), toolbox=toolbox, llm=budgeted).run()
    assert result.status == STATUS_REPORTED
    outcome = _validator(symbols, budgeted).validate(result.candidates[0], result.ledger)
    assert outcome.status == STATUS_PUBLISHED
    assert outcome.evidence_level == "L1"
    assert outcome.finding["verdict"] == "unverified"
    assert "L1" in outcome.finding["verdict_reason"]
    # No verifier call is spent on a candidate that can't become a TP.
    assert llm.steps("hunt_verify") == []


@needs_graph
def test_verifier_disagreement_caps_the_verdict():
    llm = ScriptedLLM({"sql": _sql_script()}, verifier=lambda _u: {"findings": [{
        "verdict": "false_positive", "title": "x", "line": 15, "snippet": "s", "cwe": "CWE-89",
        "verdict_reason": "value is an enum"}]})
    _runner, symbols, toolbox, budgeted, _budget = _parts(graph=_graph(), llm=llm)
    result = Investigator(_sql_hypothesis(), toolbox=toolbox, llm=budgeted).run()
    outcome = _validator(symbols, budgeted).validate(result.candidates[0], result.ledger)
    assert outcome.evidence_level == "L2"
    assert outcome.finding["verdict"] == "unverified"
    assert "disagreed" in outcome.finding["verdict_reason"]


@needs_graph
def test_hallucinated_quotes_and_unobserved_sinks_are_dropped():
    llm = ScriptedLLM({"sql": _sql_script()})
    _runner, symbols, toolbox, budgeted, _budget = _parts(graph=_graph(), llm=llm)
    result = Investigator(_sql_hypothesis(), toolbox=toolbox, llm=budgeted).run()
    validator = _validator(symbols, budgeted)

    invented = {**result.candidates[0], "quoted_lines": [
        {"file": DAO, "line": 15, "text": "return st.executeQuery(userSuppliedSql);"}]}
    out = validator.validate(invented, result.ledger)
    assert out.status == STATUS_HALLUCINATED and "does not match" in out.reasons[0]

    unseen = validator.validate(result.candidates[0], EvidenceLedger())
    assert unseen.status == STATUS_HALLUCINATED and "never shown" in unseen.reasons[0]


@needs_graph
def test_existing_finding_is_corroborated_not_republished():
    llm = ScriptedLLM({"sql": _sql_script()})
    _runner, symbols, toolbox, budgeted, _budget = _parts(graph=_graph(), llm=llm)
    result = Investigator(_sql_hypothesis(), toolbox=toolbox, llm=budgeted).run()
    existing = ExistingFindings.from_file_results([{"file_path": DAO, "findings": [
        {"line": 16, "cwe": "CWE-564", "kind": "llm", "rule_id": "llm-extra"}]}])
    out = _validator(symbols, budgeted, existing).validate(result.candidates[0], result.ledger)
    assert out.status == STATUS_CORROBORATED
    assert llm.steps("hunt_verify") == []


@needs_graph
def test_critical_file_sink_missed_by_deep_scan_is_published():
    hyp = Hypothesis(id="S2", cwe="CWE-79", vuln_class="Reflected XSS via HTTP response body",
                     sink_kind="response_body", rationale="", initial_strategy="source_first")
    report = {
        "title": "Request parameter echoed into an error response", "cwe": "CWE-79", "severity": "MEDIUM",
        "verdict": "true_positive", "confidence": 0.8,
        "source": {"file": CONTROLLER, "line": 34, "expr": '@RequestParam("msg") String msg'},
        "sink": {"file": CONTROLLER, "line": 35, "expr": "new ResponseEntity<>("},
        "verdict_reason": "msg is reflected unencoded.",
    }
    llm = ScriptedLLM({"response_body": [
        {"action": "read", "args": {"file": CONTROLLER, "start": 33, "end": 41}},
        {"action": "find_sanitizers", "args": {"kind": "response_body", "file": CONTROLLER, "start": 33, "end": 36},
         "evidence": {"sink": report["sink"], "source": report["source"]}},
        {"action": "report", "args": {"findings": [report]}},
    ]}, verifier=lambda _u: {"findings": [{"verdict": "true_positive", "title": "xss", "line": 35,
                                          "snippet": "s", "cwe": "CWE-79", "verdict_reason": "reflected"}]})
    _runner, symbols, toolbox, budgeted, _budget = _parts(graph=_graph(), llm=llm)
    result = Investigator(hyp, toolbox=toolbox, llm=budgeted).run()
    # The deep scan reported something else in this CRITICAL file, not this.
    existing = ExistingFindings.from_file_results([{"file_path": CONTROLLER, "findings": [
        {"line": 29, "cwe": "CWE-22", "kind": "llm"}]}])
    out = _validator(symbols, budgeted, existing).validate(result.candidates[0], result.ledger)
    assert out.status == STATUS_PUBLISHED
    assert out.finding["verdict"] == "true_positive"
    assert RISK[out.finding["file_path"]] == "CRITICAL"


def test_config_class_finding_uses_construct_verifier():
    hyp = Hypothesis(id="S3", cwe="CWE-798", vuln_class="Hardcoded credential", sink_kind="secret",
                     rationale="", initial_strategy="config_first")
    llm = ScriptedLLM({"secret": [
        {"action": "report", "evidence": {"sink": {"file": DAO, "line": 10, "expr": "dbPassword"}},
         "args": {"findings": [{"title": "Hardcoded DB password", "cwe": "CWE-798", "severity": "HIGH",
                                "verdict": "true_positive", "confidence": 0.9,
                                "sink": {"file": DAO, "line": 10, "expr": "dbPassword = "},
                                "quoted_lines": [{"file": DAO, "line": 10,
                                                  "text": 'private String dbPassword = "«redacted»";'}],
                                "verdict_reason": "literal password"}]}},
    ]})
    _runner, symbols, toolbox, budgeted, _budget = _parts(graph=None, llm=llm)
    result = Investigator(hyp, toolbox=toolbox, llm=budgeted).run()
    assert result.status == STATUS_REPORTED
    out = _validator(symbols, budgeted).validate(result.candidates[0], result.ledger)
    # Quoted with the redaction the model was shown: grounded, not hallucinated.
    assert out.status == STATUS_PUBLISHED
    assert out.evidence_level == "L2"
    assert out.finding["verdict"] == "true_positive"
    assert len(llm.steps("group_confirm_triage_findings")) == 1
    # The secret value never reached the model.
    assert all("Sup3rS3cretDbPass" not in user for _step, _system, user in llm.calls)


def test_loop_guards_repeat_memo_intent_cap_and_step_limit():
    repeat = {"action": "search", "args": {"pattern": "createStatement", "intent": "statements"}}
    script = [repeat, repeat] + [
        {"action": "search", "args": {"pattern": f"Statement{i}x", "intent": "statements"}} for i in range(4)
    ]
    llm = ScriptedLLM({"sql": script})
    _runner, _symbols, toolbox, budgeted, _budget = _parts(graph=None, llm=llm)
    result = Investigator(_sql_hypothesis(), toolbox=toolbox, llm=budgeted, max_steps=9).run()
    prompts = [u for _s, _sys, u in llm.steps("hunt_investigate")]
    assert "Already run" in prompts[2]
    assert "Intent 'statements' has had 3 searches" in prompts[5]
    assert result.status == STATUS_INCONCLUSIVE


def test_malformed_action_gets_one_retry_then_inconclusive():
    llm = ScriptedLLM({"sql": ["not json at all", '{"action": "teleport"}']})
    _runner, _symbols, toolbox, budgeted, _budget = _parts(graph=None, llm=llm)
    result = Investigator(_sql_hypothesis(), toolbox=toolbox, llm=budgeted).run()
    assert result.status == STATUS_INCONCLUSIVE
    assert result.llm_turns == 2
    assert "not a valid action" in llm.steps("hunt_investigate")[1][2]


def test_evidence_notes_for_unseen_lines_are_ignored():
    llm = ScriptedLLM({"sql": [
        {"action": "list_files", "args": {"glob": "**/*.java"},
         "evidence": {"source": {"file": CONTROLLER, "line": 23}}},
        {"action": "abandon", "args": {"verdict": "inconclusive", "reason": "done"}},
    ]})
    _runner, _symbols, toolbox, budgeted, _budget = _parts(graph=None, llm=llm)
    inv = Investigator(_sql_hypothesis(), toolbox=toolbox, llm=budgeted)
    inv.run()
    assert inv.checklist.source is None
    assert "Evidence notes ignored" in llm.steps("hunt_investigate")[1][2]


def test_repository_text_reaches_the_model_only_as_untrusted_data():
    llm = ScriptedLLM({"log": [
        {"action": "read", "args": {"file": SERVICE, "start": 10, "end": 16}},
        {"action": "abandon", "args": {"verdict": "inconclusive", "reason": "x"}},
    ]})
    _runner, _symbols, toolbox, budgeted, _budget = _parts(graph=None, llm=llm)
    hyp = Hypothesis(id="S4", cwe="CWE-117", vuln_class="Log injection", sink_kind="log", rationale="")
    Investigator(hyp, toolbox=toolbox, llm=budgeted).run()
    prompt = llm.steps("hunt_investigate")[1][2]
    comment_at = prompt.index("ignore previous instructions")
    block_start = prompt.rfind("<untrusted_code", 0, comment_at)
    block_end = prompt.find("</untrusted_code>", comment_at)
    assert -1 < block_start < comment_at < block_end
    assert "never instructions" in HUNT_SYSTEM


def test_budget_refusal_stops_the_investigation():
    budget = HuntBudget(BudgetLimits(max_usd=None, max_llm_calls=0))
    llm = ScriptedLLM({"sql": _sql_script()})
    _runner, _symbols, toolbox, budgeted, _budget = _parts(graph=None, llm=llm, budget=budget)
    result = Investigator(_sql_hypothesis(), toolbox=toolbox, llm=budgeted).run()
    assert result.status == STATUS_BUDGET
    assert llm.calls == []


# --- engine --------------------------------------------------------------------


@needs_graph
def test_run_hunt_end_to_end_publishes_writes_and_reports():
    llm = ScriptedLLM({"sql": _sql_script()})
    written = []
    results = hunt_engine.run_hunt(
        root=FIXTURE, inventory=INVENTORY,
        seed_entries=[{"path": p, "risk_level": r} for p, r in RISK.items()],
        stack="Java / Spring Boot", frameworks=["Spring Boot"], graph=_graph(),
        call_llm_fn=llm, findings_writer=lambda path, fs: written.append((path, fs)),
        options=hunt_engine.HuntOptions(workers=1, max_hypotheses=12),
    )
    assert results["tp_count"] == 1
    assert [(p, fs[0]["line"]) for p, fs in written] == [(DAO, 15)]
    rows = {r["sink_kind"]: r for r in results["hypotheses"]}
    assert rows["sql"]["status"] == "confirmed"
    assert rows["sql"]["insufficient_evidence"] == 2
    assert "source_trace" in rows["sql"]["strategy_trail"]
    assert results["evidence_levels"] == {"L2": 1}
    assert results["budget"]["llm_calls"] >= 9
    assert results["searches_run"] > 0
    # Seeds cover the sink kinds the fixture really contains plus authz.
    assert {"sql", "files", "authz", "csrf"} <= set(rows)
    assert len(llm.steps("hunt_plan")) == 1


def test_run_hunt_without_rg_is_a_reported_no_op():
    results = hunt_engine.run_hunt(root=FIXTURE, inventory=INVENTORY, seed_entries=[], stack="java",
                                   call_llm_fn=ScriptedLLM(), rg_binary="")
    assert results["skipped_reason"] == "ripgrep (rg) is not installed"
    assert results["files"] == []


def test_run_hunt_budget_exhaustion_is_reported():
    llm = ScriptedLLM({"sql": _sql_script()})
    results = hunt_engine.run_hunt(
        root=FIXTURE, inventory=INVENTORY, seed_entries=[], stack="java", call_llm_fn=llm,
        options=hunt_engine.HuntOptions(workers=2, max_llm_calls=1, max_usd=None),
    )
    # The single allowed call went to the planner; every investigation stopped on budget.
    assert len(llm.calls) == 1
    assert results["budget_stopped"] is True
    assert set(results["hypothesis_status"]) == {"budget"}
    assert results["budget"]["refusals"].get("llm_calls")


# --- graph node ------------------------------------------------------------------


@pytest.fixture()
def agent(monkeypatch):
    pytest.importorskip("langgraph")
    from app.config import settings
    from app.services.agent_bridge import _load_agent_module

    monkeypatch.setattr(settings, "sast_framework_path", str(_ENGINE_DIR))
    sys.modules.pop("sast_scan_agent", None)
    return _load_agent_module()


def test_hunt_node_is_a_no_op_unless_enabled(agent):
    base = {"_tracer": agent.AgentTrace(verbose=False), "local_path": str(FIXTURE), "use_llm": True}
    assert agent.node_hunt_security({**base}) == {}
    assert agent.node_hunt_security({**base, "hunt_mode": "off"}) == {}
    assert agent.node_hunt_security({**base, "hunt_mode": "agentic", "use_llm": False}) == {}


def test_hunt_node_reports_missing_ripgrep(agent, monkeypatch):
    monkeypatch.setenv("RG_PATH", "/nonexistent/rg")
    out = agent.node_hunt_security({"_tracer": agent.AgentTrace(verbose=False), "local_path": str(FIXTURE),
                                    "use_llm": True, "hunt_mode": "agentic"})
    assert out["hunt_scan_results"]["skipped_reason"] == "ripgrep (rg) is not installed"


@needs_graph
def test_full_graph_with_hunt_writes_findings_and_reports(agent, monkeypatch, tmp_path):
    import shutil

    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE, repo)
    scripted = ScriptedLLM({"sql": _sql_script()}, default='{"findings": []}')
    llm_client = sys.modules["llm_client"]

    def fake_bedrock(system, user, model_id, *_args, step=None, usage=None, meta_out=None, **_kwargs):
        # The real transport records usage itself; so must its stand-in.
        if usage is not None:
            llm_client.record_llm_usage(usage, step, 10, 5, provider="bedrock", model=model_id)
        if meta_out is not None:
            meta_out.update({"input_tokens": 10, "output_tokens": 5})
        return scripted(system, user, step=step)

    monkeypatch.setattr(llm_client, "_call_bedrock", fake_bedrock)
    written = []
    state = {
        "local_path": str(repo), "scope": None, "context_note": "", "verbose": False,
        "verbose_files": False, "persist_to_disk": False, "use_llm": True,
        "_tracer": agent.AgentTrace(verbose=False),
        "usage": agent.init_usage("bedrock", None, cost_cutoff_usd=0),
        # Keep every other LLM stage out of the way: this test is about the hunt.
        "deep_scan_file_cap": 0, "triage_mode": "regex_only", "inter_file_flow": False,
        "derive_runtime_rules": False, "group_triage_mode": False, "confirm_triage_groups": False,
        "joern_dataflow": False, "joern_scan_queries": False,
        "hunt_mode": "agentic", "hunt_workers": 1, "hunt_budget_usd": 5.0,
        "findings_writer": lambda path, fs: written.append((path, [f.get("kind") for f in fs])),
    }
    final = agent.invoke_graph(agent.build_graph(), state)

    hunt = final["report"]["hunt"]
    assert hunt["tp_count"] == 1
    assert ("src/main/java/com/acme/repo/OrderDao.java", ["hunt"]) in written
    assert final["report"]["tp_count"] >= 1
    usage = agent.usage_cost_summary(final["usage"])
    assert usage["by_step"]["hunt_investigate"]["calls"] >= 8
    assert "hunt_verify" in usage["by_step"]


@needs_graph
def test_a_search_that_led_to_a_confirmed_finding_is_promoted_as_a_learned_rule():
    script = _sql_script()
    # The investigator writes its own search first, which surfaces the sink.
    script.insert(0, {"thought": "concatenated SQL", "strategy": "sink_search", "action": "search",
                      "args": {"pattern": r"executeQuery\(\"SELECT \* FROM orders WHERE name = '\" \+",
                               "glob": "**/*.java", "intent": "concatenated order queries"}})
    llm = ScriptedLLM({"sql": script})
    results = hunt_engine.run_hunt(
        root=FIXTURE, inventory=INVENTORY, seed_entries=[{"path": p, "risk_level": r} for p, r in RISK.items()],
        stack="Java", graph=_graph(), call_llm_fn=llm,
        options=hunt_engine.HuntOptions(workers=1, max_hypotheses=1),
    )
    assert results["tp_count"] == 1
    learned = results["learned_rules"]
    assert [r["status"] for r in learned] == ["promoted"]
    assert learned[0]["positives"] == [f"{DAO}:15"]
    # DAO plus the same construct in the test file: under the noise ceiling.
    assert learned[0]["repo_matches"] == 2
    assert learned[0]["rule"]["id"].startswith("learned-cwe-89")


@needs_graph
def test_rule_learned_by_one_scans_hunt_is_caught_by_the_next_scans_catalog(agent):
    """Scan 1's hunt promotes its search; the app merges it onto the project;
    scan 2's plain catalog pass finds the same construct without the hunt."""
    from app.services.learned_rules import merge_promoted_rules

    script = _sql_script()
    script.insert(0, {"action": "search", "args": {
        "pattern": r"executeQuery\(\"SELECT \* FROM orders WHERE name = '\" \+", "intent": "concatenated queries"}})
    results = hunt_engine.run_hunt(
        root=FIXTURE, inventory=INVENTORY, seed_entries=[{"path": p, "risk_level": r} for p, r in RISK.items()],
        stack="Java", graph=_graph(), call_llm_fn=ScriptedLLM({"sql": script}),
        options=hunt_engine.HuntOptions(workers=1, max_hypotheses=1),
    )
    project_rules = merge_promoted_rules(None, {"report": {"hunt": results}}, scan_id="scan-1")
    assert project_rules and project_rules[0]["id"].startswith("learned-cwe-89-")

    entries = [{"path": DAO, "module": "(root)", "lang": "java", "risk_level": "MEDIUM"}]
    state = {
        "_tracer": agent.AgentTrace(verbose=False), "local_path": str(FIXTURE), "use_llm": False,
        "triage_mode": "regex_only", "learned_rules": project_rules,
        "module_plan": {"files": entries, "deep_scan_paths": [], "triage_scan_paths": [DAO]},
    }
    found = agent.node_scan_triage_files(state)["triage_scan_results"]
    hits = [(f["rule_id"], f["line"]) for fr in found["files"] for f in fr["findings"]]
    assert (project_rules[0]["id"], 15) in hits

    # A stale rule that no longer compiles, or that collides with a catalog
    # id, is skipped rather than breaking the scan.
    broken = [{"id": "learned-x", "pattern": "(unclosed"}, {"id": "java-sql-concat", "pattern": "x"}]
    assert agent._learned_rules({"learned_rules": broken}, {"java-sql-concat"}) == []


def test_disabled_hunt_says_so_in_the_log(agent, capsys):
    agent.node_hunt_security({"_tracer": agent.AgentTrace(verbose=True), "local_path": str(FIXTURE), "use_llm": True})
    out = capsys.readouterr().out
    assert "### Hunting vulnerabilities (agentic)" in out
    assert "Agentic hunt is off for this project" in out



def test_final_turns_accept_only_a_verdict():
    keep_searching = [{"action": "search", "args": {"pattern": f"thing{i}x", "intent": f"i{i}"}} for i in range(10)]
    llm = ScriptedLLM({"sql": keep_searching})
    _runner, _symbols, toolbox, budgeted, _budget = _parts(graph=None, llm=llm)
    result = Investigator(_sql_hypothesis(), toolbox=toolbox, llm=budgeted, max_steps=5).run()
    prompts = [u for _s, _sys, u in llm.steps("hunt_investigate")]
    # Steps 1-3 run tools; then the verdict-only phase (2 attempts), never a 4th search.
    assert result.steps == 3
    assert "FINAL TURN" in prompts[3]
    assert result.status == STATUS_INCONCLUSIVE and "valid verdict" in result.reason


def test_final_turn_report_is_accepted_with_its_gaps():
    sink_only = {**SQL_REPORT, "source": None, "path": []}
    llm = ScriptedLLM({"sql": [
        {"action": "read", "args": {"file": DAO, "start": 12, "end": 20}},
        {"action": "read", "args": {"file": DAO, "start": 1, "end": 11}},
        {"action": "report", "args": {"findings": [sink_only]}},
    ]})
    _runner, _symbols, toolbox, budgeted, _budget = _parts(graph=None, llm=llm)
    result = Investigator(_sql_hypothesis(), toolbox=toolbox, llm=budgeted, max_steps=4).run()
    assert result.status == STATUS_REPORTED
    assert result.insufficient_evidence == 0  # not refused: it was the final turn
    assert any(g.startswith("source") for g in result.candidates[0]["_evidence_gaps"])


def test_spend_share_forces_a_verdict():
    keep_searching = [{"action": "search", "args": {"pattern": f"thing{i}x", "intent": f"i{i}"}} for i in range(10)]
    llm = ScriptedLLM({"sql": keep_searching + [{"action": "abandon", "args": {"verdict": "inconclusive", "reason": "x"}}]})
    _runner, _symbols, toolbox, budgeted, _budget = _parts(graph=None, llm=llm)
    # Pretend the first turn already used the whole share.
    budgeted.spent_usd = 1.0
    inv = Investigator(_sql_hypothesis(), toolbox=toolbox, llm=budgeted, max_steps=12, spend_cap_usd=0.5)
    inv.run()
    assert "FINAL TURN" in llm.steps("hunt_investigate")[0][2]


def test_flow_hypothesis_starts_with_source_and_sink_established():
    flow = {"sink_kind": "sql", "entry_tier": "framework", "hops": [
        {"file": CONTROLLER, "line": 23, "role": "source", "name": "search", "label": "search(...)"},
        {"file": SERVICE, "line": 16, "role": "hop", "name": "search"},
        {"file": DAO, "line": 15, "role": "sink", "name": "findByName", "label": "Statement.executeQuery(...)"},
    ]}
    hyp = Hypothesis(id="F1", cwe="CWE-89", vuln_class="SQL injection (flow)", sink_kind="sql",
                     rationale="flow", origin="flow", flow=flow)
    llm = ScriptedLLM({"sql": [{"action": "abandon", "args": {"verdict": "inconclusive", "reason": "x"}}]})
    _runner, _symbols, toolbox, budgeted, _budget = _parts(graph=None, llm=llm)
    inv = Investigator(hyp, toolbox=toolbox, llm=budgeted)
    inv.run()
    assert inv.checklist.source["line"] == 23 and inv.checklist.sink["line"] == 15
    assert inv.checklist.path and inv.checklist.path[0]["file"] == SERVICE


def test_worker_thread_narration_reaches_the_calling_thread():
    import threading as _threading

    seen = []
    caller = _threading.get_ident()
    llm = ScriptedLLM({"sql": _sql_script()})
    hunt_engine.run_hunt(
        root=FIXTURE, inventory=INVENTORY, seed_entries=[], stack="java", call_llm_fn=llm,
        options=hunt_engine.HuntOptions(workers=3, max_hypotheses=4),
        on_event=lambda msg: seen.append((_threading.get_ident(), msg)),
    )
    assert seen and all(tid == caller for tid, _ in seen)
    messages = [m for _t, m in seen]
    assert any(m.startswith("Hunting hypothesis 1/") for m in messages)
    assert any(": inconclusive" in m or ": refuted" in m or ": reported" in m for m in messages)
