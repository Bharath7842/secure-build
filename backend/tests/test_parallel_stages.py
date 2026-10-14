"""Parallel scan stages (plan Part E): the fan-out graph matches the
sequential one, stage budget reservations hold under concurrency, throttling
backs off and lowers concurrency, the process-pool regex pass matches the
in-process one, and stage-tagged logs drive progress without jumping ahead."""

import contextlib
import io
import json
import threading
from pathlib import Path

import pytest

pytest.importorskip("langgraph")

from app.config import settings  # noqa: E402
from app.services.agent_bridge import _load_agent_module  # noqa: E402

_ENGINE_DIR = Path(__file__).resolve().parents[1] / "sast_engine"


@pytest.fixture()
def agent(monkeypatch):
    import sys

    monkeypatch.setattr(settings, "sast_framework_path", str(_ENGINE_DIR))
    sys.modules.pop("sast_scan_agent", None)
    return _load_agent_module()


@pytest.fixture()
def llm_client(agent):
    return agent.llm_client


def _repo(tmp_path):
    (tmp_path / "pom.xml").write_text("<project/>\n", encoding="utf-8")
    base = tmp_path / "src" / "main" / "java" / "com" / "acme"
    for pkg, name, body in (
        ("repository", "OrderDao", 'class OrderDao { String q(String id) { return "SELECT * FROM t WHERE id = " + id; } }\n'),
        ("web", "PingController", 'class PingController { void p(String h) throws Exception { Runtime.getRuntime().exec("ping " + h); } }\n'),
        ("util", "Cfg", 'class Cfg { String password = "Pr0d!pass"; }\n'),
    ):
        (base / pkg).mkdir(parents=True, exist_ok=True)
        (base / pkg / f"{name}.java").write_text(body, encoding="utf-8")
    return tmp_path


def _run(agent, root, *, parallel, stage_log=None):
    written = []
    state = {
        "local_path": str(root), "scope": None, "context_note": "",
        "verbose": False, "verbose_files": False, "use_llm": False, "persist_to_disk": False,
        # No deep-scan slots: every file goes to the regex triage tier, so
        # both graphs produce real findings without an LLM.
        "deep_scan_file_cap": 0, "backfill_deep_scan": False,
        "joern_dataflow": False, "joern_scan_queries": False,
        "usage": agent.init_usage(None, None),
        "findings_writer": lambda path, findings: written.extend((path, f["rule_id"], f["line"]) for f in findings),
        "parallel_stages": parallel,
        "_tracer": agent.AgentTrace(verbose=False),
    }
    if stage_log is not None:
        state["_stage_log_context"] = stage_log
    final = agent.invoke_graph(agent.build_graph(parallel=parallel), state)
    return final, sorted(written)


def test_parallel_graph_matches_sequential(agent, tmp_path):
    root = _repo(tmp_path)
    seq_state, seq_written = _run(agent, root, parallel=False)
    par_state, par_written = _run(agent, root, parallel=True)
    assert seq_written and par_written == seq_written
    assert par_state["report"] == seq_state["report"]
    assert par_state["report"]["unverified_count"] >= 3


def test_parallel_graph_shape(agent):
    graph = agent.build_graph(parallel=True).get_graph()
    nodes = set(graph.nodes)
    assert {"fan_out", "flows", "scan_deep_files", "scan_triage_files"} <= nodes
    assert not {"discover_flows", "verify_flow_slices", "joern_scan"} & nodes
    edges = {(e.source, e.target) for e in graph.edges}
    for branch in ("flows", "scan_deep_files", "scan_triage_files"):
        assert ("fan_out", branch) in edges
        assert (branch, "group_triage_findings") in edges


def test_each_parallel_stage_runs_in_its_log_context_and_reports_finishing(agent, tmp_path, capsys):
    seen = []

    @contextlib.contextmanager
    def stage_log(stage):
        seen.append(stage)
        yield

    _run(agent, _repo(tmp_path), parallel=True, stage_log=stage_log)
    assert sorted(seen) == ["deep", "flows", "triage"]
    out = capsys.readouterr().out
    for stage in ("deep", "flows", "triage"):
        assert f"Stage finished: {stage}" in out


# --- stage budget reservations --------------------------------------------------

def test_stage_may_spend_its_share_then_only_released_budget(llm_client):
    usage = llm_client.init_usage("bedrock", None)
    usage["cost_cutoff_usd"] = 1.0
    llm_client.reserve_stage_budgets(usage)
    spent = usage[llm_client.STAGE_BUDGET_USAGE_KEY]["spent"]

    spent["deep"] = 0.55
    usage["cost_usd"] = 0.55
    with pytest.raises(llm_client.LlmBudgetExhausted):
        llm_client._resolve_provider_for_call(usage, "bedrock", None, "scan_deep_files")
    # Other stages still have their reserved shares.
    llm_client._resolve_provider_for_call(usage, "bedrock", None, "scan_triage_files")
    assert not usage.get("budget_exhausted")

    # Triage finishes having used only 0.05 of its 0.35: the rest is released.
    spent["triage"] = 0.05
    usage["cost_usd"] = 0.60
    llm_client.finish_stage(usage, "triage")
    llm_client._resolve_provider_for_call(usage, "bedrock", None, "scan_deep_files")


def test_concurrent_stages_never_spend_past_the_cutoff(llm_client, monkeypatch):
    cost_per_call = 0.01
    monkeypatch.setattr(llm_client, "llm_cost_usd", lambda *a, **k: cost_per_call)

    def fake_bedrock(system, user, model, max_tokens, temperature, retries, *, usage, step, meta_out=None, **_k):
        llm_client.record_llm_usage(usage, step, 10, 10, provider="bedrock", model=model)
        return "{}"

    monkeypatch.setattr(llm_client, "_call_bedrock", fake_bedrock)
    usage = llm_client.init_usage("bedrock", None)
    usage["cost_cutoff_usd"] = 1.0
    llm_client.reserve_stage_budgets(usage)

    def worker(step):
        while True:
            try:
                llm_client.call_llm("s", "u", usage=usage, step=step)
            except llm_client.LlmBudgetExhausted:
                return

    workers = 4
    threads = [threading.Thread(target=worker, args=(step,))
               for step in ("scan_deep_files", "verify_flow_slices", "scan_triage_files") for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    total = usage["cost_usd"]
    in_flight = len(threads)
    assert total <= 1.0 + in_flight * cost_per_call + 1e-9
    spent = usage[llm_client.STAGE_BUDGET_USAGE_KEY]["spent"]
    # Nothing finished, so no stage borrowed past its share (beyond in-flight overshoot).
    for stage, share in llm_client.DEFAULT_STAGE_SHARES.items():
        assert spent[stage] <= share + workers * cost_per_call + 1e-9


# --- throttling ------------------------------------------------------------------

class _Throttle(Exception):
    def __init__(self):
        super().__init__("An error occurred (ThrottlingException) when calling InvokeModel")
        self.response = {"Error": {"Code": "ThrottlingException"}}


def test_throttling_backs_off_with_jitter_and_lowers_concurrency(llm_client, monkeypatch):
    limiter = llm_client.AdaptiveLimiter(8)
    monkeypatch.setattr(llm_client, "_LIMITER", limiter)
    waits = []
    monkeypatch.setattr(llm_client.time, "sleep", waits.append)
    calls = {"n": 0}

    class FakeBedrock:
        def invoke_model(self, **_kwargs):
            calls["n"] += 1
            if calls["n"] <= 2:
                raise _Throttle()
            body = {"content": [{"text": "ok"}], "usage": {"input_tokens": 5, "output_tokens": 1}, "stop_reason": "end_turn"}
            return {"body": io.BytesIO(json.dumps(body).encode())}

    monkeypatch.setattr(llm_client, "_bedrock", FakeBedrock())
    text = llm_client.call_llm("s", "u", usage=llm_client.init_usage("bedrock", None), step="scan_deep_files", retries=1)
    assert text == "ok"
    assert calls["n"] == 3  # two throttles did not use up the single ordinary retry
    assert len(waits) == 2 and all(w > 0 for w in waits)
    assert limiter.limit == 2  # 8 -> 4 -> 2


def test_limiter_recovers_one_slot_per_run_of_successes(llm_client):
    limiter = llm_client.AdaptiveLimiter(4)
    limiter.on_throttle()
    assert limiter.limit == 2
    for _ in range(llm_client.LIMITER_RECOVER_AFTER):
        limiter.on_success()
    assert limiter.limit == 3


# --- process-pool regex pass ------------------------------------------------------

def test_process_pool_regex_pass_matches_in_process(agent, tmp_path):
    lfs = agent.llm_file_scan
    regex_scan = agent.regex_scan
    root = _repo(tmp_path)
    rules = regex_scan.load_rules(_ENGINE_DIR / "rules")
    entries = [
        {"path": str(p.relative_to(root)).replace("\\", "/"), "module": "(root)", "lang": "java", "risk_level": "MEDIUM"}
        for p in sorted(root.rglob("*.java"))
    ]

    def run(processes):
        out = lfs.scan_triage_files(module_plan={"files": entries}, entries=entries, repo_root=root,
                                    rules=rules, regex_processes=processes)
        return sorted((fr["file_path"], f["rule_id"], f["line"], f["matched_text"])
                      for fr in out["files"] for f in fr["findings"])

    prescanned = regex_scan.scan_files_in_processes(
        [(e["path"], "(root)", "java", None) for e in entries], repo_root=root, rules=rules, workers=2,
    )
    assert prescanned is not None and set(prescanned) == {e["path"] for e in entries}
    in_process = run(False)
    assert in_process and run(True) == in_process


# --- stage-tagged logs and progress -------------------------------------------------

def test_capture_prefix_tags_printed_and_logged_lines(tmp_path, monkeypatch):
    from app.services import scan_log

    monkeypatch.setattr(settings, "scan_logs_dir", str(tmp_path))
    scan_log.reset("s-tag")
    with scan_log.capture("s-tag"):
        print("before")
        with scan_log.capture("s-tag", prefix="[[stage:deep]] "):
            print("### Scanning CRITICAL files (deep scan)")
            scan_log.log("s-tag", "  Saved 1 finding(s) for a.java")
        print("after")
    lines = [row["line"] for row in scan_log.get_logs("s-tag")[0]]
    assert lines == [
        "before",
        "[[stage:deep]] ### Scanning CRITICAL files (deep scan)",
        "[[stage:deep]]   Saved 1 finding(s) for a.java",
        "after",
    ]


def test_tagged_banners_do_not_jump_progress_but_finished_stages_do():
    from app.services.scan_progress import infer_progress_from_lines

    fan_out = [
        "### Deriving runtime regex",
        "[[stage:deep]] ### Scanning CRITICAL files (deep scan)",
        "[[stage:triage]] ### Scanning MEDIUM/LOW files (triage)",
    ]
    assert infer_progress_from_lines(fan_out) == 80
    assert infer_progress_from_lines(fan_out + ["[[stage:triage]] Stage finished: triage"]) == 84
    done = fan_out + [f"[[stage:{s}]] Stage finished: {s}" for s in ("triage", "flows", "deep")]
    assert infer_progress_from_lines(done) == 97
    assert infer_progress_from_lines(done + ["### Grouping MEDIUM/LOW findings"]) == 98
