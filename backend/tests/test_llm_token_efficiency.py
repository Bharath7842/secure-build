"""Token-efficiency behaviour of the SAST LLM stages: stable cacheable system
prompts, compact catalogs, deduplicated triage/flow context, provider prompt
caching, and the cross-scan result cache. All LLM calls are stubbed."""

import io
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("boto3")
pytest.importorskip("langgraph")

from app.config import settings  # noqa: E402
from app.services.agent_bridge import _load_agent_module  # noqa: E402

_ENGINE_DIR = Path(__file__).resolve().parents[1] / "sast_engine"


@pytest.fixture()
def agent(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setattr(settings, "sast_framework_path", str(_ENGINE_DIR))
    sys.modules.pop("sast_scan_agent", None)
    return _load_agent_module()


@pytest.fixture()
def lfs(agent):
    return sys.modules["pipeline.llm_file_scan"]


@pytest.fixture()
def llm(agent):
    return sys.modules["llm_client"]


@pytest.fixture()
def fv(agent):
    return sys.modules["pipeline.flow_verify"]


@pytest.fixture()
def cg(agent):
    return sys.modules["pipeline.call_graph"]


@pytest.fixture()
def rules(agent):
    return sys.modules["pipeline.regex_scan"].load_rules(_ENGINE_DIR / "rules")


# --- deep-scan prompt shape --------------------------------------------------

_CATALOG = [
    {"id": "java-sqli", "title": "SQL injection", "description": "String-built SQL",
     "cwe": "CWE-89", "severity": "HIGH", "owasp": "A03:2021-Injection"},
]


def test_system_prompt_carries_schema_and_compact_catalog(lfs):
    system = lfs.build_system_prompt(_CATALOG, "Java")
    assert '{"findings": [' in system
    assert "- java-sqli | CWE-89 | HIGH | SQL injection: String-built SQL" in system
    # No indented JSON dump of the catalog, and no per-rule OWASP repetition.
    assert '"description":' not in system


def test_user_prompt_has_no_schema(lfs):
    user = lfs.build_user_prompt(file_path="A.java", chunk_text="int a;\nint b;", start_line=1)
    assert "Output format" not in user and '"verdict"' not in user
    assert "1: int a;" in user and "2: int b;" in user


def test_system_prompt_identical_across_same_language_files(tmp_path, lfs, rules):
    for name in ("A.java", "B.java"):
        (tmp_path / name).write_text(f"class {name[0]} {{ void f() {{}} }}\n", encoding="utf-8")
    systems = []

    def fake(system, user, **kwargs):
        systems.append(system)
        assert kwargs.get("json_mode") is True
        return '{"findings": []}'

    entries = [{"path": p, "risk_level": "CRITICAL", "lang": "java"} for p in ("A.java", "B.java")]
    result = lfs.scan_deep_files(
        module_plan={"files": entries}, entries=entries, repo_root=tmp_path, rules=rules,
        call_llm_fn=fake, file_workers=1,
    )
    assert len(systems) == 2 and systems[0] == systems[1]
    assert result["chunk_errors"] == 0  # an empty envelope is a clean answer, not an error


def test_catalog_owasp_filled_locally_for_catalog_rule(lfs):
    finding = lfs.normalize_finding(
        {"verdict": "true_positive", "rule_id": "java-sqli", "line": 1, "cwe": "CWE-89"},
        file_path="A.java", chunk_start=1, chunk_end=1,
        rule_owasp=lfs.catalog_owasp_index(_CATALOG),
    )
    assert finding["owasp_category"] == "A03:2021-Injection"


def test_license_header_collapsed_but_line_numbers_kept(lfs):
    lines = ["/*", " * Copyright 2020 Example", " * Licensed under Apache 2.0", " */",
             "package x;", "class A {}"]
    span = lfs.leading_license_header_span(lines)
    assert span == (1, 4)
    user = lfs.build_user_prompt(
        file_path="A.java", chunk_text="\n".join(lines), start_line=1, omit_span=span,
    )
    assert "1-4: [license header omitted]" in user
    assert "Copyright" not in user
    assert "5: package x;" in user and "6: class A {}" in user


@pytest.mark.parametrize("lines", [
    ["/* just a note", " * about this file", " */", "class A {}"],   # no license text
    ["/* Copyright */ int x = 1;", "", "", ""],                       # code on closing line
    ["#include <licence.h>", "#include <b.h>", "#include <c.h>", "int main;"],  # not comments
])
def test_license_header_left_alone_when_not_a_license_block(lfs, lines):
    assert lfs.leading_license_header_span(lines) is None


def test_skeleton_for_chunk_drops_in_chunk_lines_and_prefers_taint(lfs):
    entries = [(1, "import", "import a;"), (50, "taint", "request.getParameter(x)"),
               (500, "decl", "void far() {"), (600, "taint", "stmt.executeQuery(sql)")]
    out = lfs.skeleton_for_chunk(entries, 40, 520)
    assert "50:" not in out and "500:" not in out  # inside the chunk
    assert "1: import a;" in out and "600: stmt.executeQuery(sql)" in out
    tight = lfs.skeleton_for_chunk(entries, 40, 520, max_chars=40)
    assert "600:" in tight and "1: import a;" not in tight  # taint kept first
    assert "skeleton truncated" in tight


# --- JSON envelope parsing ------------------------------------------------------

def test_parse_unwraps_envelopes_and_treats_empty_as_clean(llm):
    assert llm.parse_llm_json_array('{"findings": [{"line": 3}]}') == ([{"line": 3}], None)
    assert llm.parse_llm_json_array('{"decisions": []}') == ([], None)
    assert llm.parse_llm_json_array('{"rules": [{"id": "r"}]}') == ([{"id": "r"}], None)
    assert llm.parse_llm_json_array('[{"line": 1}]') == ([{"line": 1}], None)  # Ollama-style


# --- Bedrock prompt caching + accounting -------------------------------------

class _FakeBedrock:
    def __init__(self, usage, text='"findings": []}', stop_reason="end_turn"):
        self.bodies = []
        self.usage = usage
        self.text = text
        self.stop_reason = stop_reason

    def invoke_model(self, **kwargs):
        self.bodies.append(json.loads(kwargs["body"]))
        payload = {"content": [{"text": self.text}], "usage": self.usage,
                   "stop_reason": self.stop_reason}
        return {"body": io.BytesIO(json.dumps(payload).encode())}


def test_bedrock_caches_large_system_prompt_and_prices_cache_tokens(llm, monkeypatch):
    fake = _FakeBedrock({"input_tokens": 100, "output_tokens": 10,
                         "cache_read_input_tokens": 5000, "cache_creation_input_tokens": 0})
    monkeypatch.setattr(llm, "_bedrock", fake)
    usage = llm.init_usage("bedrock", "us.anthropic.claude-haiku-4-5-20251001-v1:0")
    text = llm.call_llm("x" * 20_000, "user", usage=usage, step="scan_deep_files", json_mode=True)
    assert text == '{"findings": []}'
    system = fake.bodies[0]["system"]
    assert isinstance(system, list) and system[0]["cache_control"] == {"type": "ephemeral"}
    # input_tokens is the logical prompt size; the cache read only discounts cost.
    assert usage["input_tokens"] == 5100
    assert usage["cache_read_input_tokens"] == 5000
    expected = llm.llm_cost_usd(5100, 10, "bedrock", "haiku", cache_read_tokens=5000)
    assert usage["cost_usd"] == pytest.approx(expected)
    assert expected < llm.llm_cost_usd(5100, 10, "bedrock", "haiku")
    summary = llm.usage_cost_summary(usage)
    assert summary["cache_read_input_tokens"] == 5000
    assert summary["by_step"]["scan_deep_files"]["cache_read_input_tokens"] == 5000


def test_bedrock_small_system_prompt_sent_as_plain_string(llm, monkeypatch):
    fake = _FakeBedrock({"input_tokens": 10, "output_tokens": 2})
    monkeypatch.setattr(llm, "_bedrock", fake)
    llm.call_llm("short system", "user", usage=llm.init_usage(), step="t", json_mode=True)
    assert fake.bodies[0]["system"] == "short system"


def test_empty_bedrock_response_is_still_recorded(llm, monkeypatch):
    fake = _FakeBedrock({"input_tokens": 10, "output_tokens": 0}, text="")
    monkeypatch.setattr(llm, "_bedrock", fake)
    monkeypatch.setattr(llm.time, "sleep", lambda _s: None)
    usage = llm.init_usage()
    llm.call_llm("s", "u", usage=usage, step="t", retries=2)
    assert len(usage["calls"]) == 2  # both billed attempts, not just the last


# --- cross-scan result cache -------------------------------------------------

class _MemoryCache:
    def __init__(self):
        self.store = {}
        self.puts = 0

    def get(self, key):
        return self.store.get(key)

    def put(self, key, *, step, model, text, input_tokens=None, output_tokens=None):
        self.puts += 1
        self.store[key] = {"text": text, "input_tokens": input_tokens, "output_tokens": output_tokens}


def test_result_cache_hit_skips_provider_and_records_savings(llm, monkeypatch):
    fake = _FakeBedrock({"input_tokens": 40, "output_tokens": 8})
    monkeypatch.setattr(llm, "_bedrock", fake)
    cache = _MemoryCache()
    usage = llm.init_usage()
    usage[llm.RESULT_CACHE_USAGE_KEY] = cache
    first = llm.call_llm("s", "u", usage=usage, step="scan_deep_files", json_mode=True)
    second = llm.call_llm("s", "u", usage=usage, step="scan_deep_files", json_mode=True)
    assert first == second and len(fake.bodies) == 1
    summary = llm.usage_cost_summary(usage)
    assert summary["call_count"] == 1
    assert summary["result_cache_hits"] == 1
    assert summary["result_cache_saved_tokens"] == 48
    assert summary["by_step"]["scan_deep_files"]["result_cache_hits"] == 1
    # A different prompt (changed code) misses.
    llm.call_llm("s", "u2", usage=usage, step="scan_deep_files", json_mode=True)
    assert len(fake.bodies) == 2


@pytest.mark.parametrize("text,stop_reason", [
    ('"findings": [{"line": 1', "max_tokens"),   # truncated
    ("not json at all", "end_turn"),              # garbled
])
def test_result_cache_never_stores_incomplete_responses(llm, monkeypatch, text, stop_reason):
    monkeypatch.setattr(llm, "_bedrock", _FakeBedrock({"input_tokens": 1, "output_tokens": 1},
                                                       text=text, stop_reason=stop_reason))
    cache = _MemoryCache()
    usage = llm.init_usage()
    usage[llm.RESULT_CACHE_USAGE_KEY] = cache
    llm.call_llm("s", "u", usage=usage, step="t", json_mode=True)
    assert cache.puts == 0


def test_result_cache_ignores_non_json_mode_calls(llm, monkeypatch):
    monkeypatch.setattr(llm, "_bedrock", _FakeBedrock({"input_tokens": 1, "output_tokens": 1}))
    cache = _MemoryCache()
    usage = llm.init_usage()
    usage[llm.RESULT_CACHE_USAGE_KEY] = cache
    llm.call_llm("s", "u", usage=usage, step="t")
    assert cache.puts == 0


def test_result_cache_key_covers_model_and_prompt_version(llm, monkeypatch):
    base = dict(provider="bedrock", model="m1", max_tokens=10, temperature=0.0, json_mode=True)
    key = llm.result_cache_key("s", "u", **base)
    assert key != llm.result_cache_key("s", "u", **{**base, "model": "m2"})
    monkeypatch.setattr(llm, "RESULT_CACHE_VERSION", "999")
    assert key != llm.result_cache_key("s", "u", **base)


def test_db_result_cache_round_trip(tmp_path):
    from app import db as db_module
    from app.db import init_db
    from app.models import Project
    from app.services.llm_result_cache import DbLlmResultCache

    init_db(f"sqlite:///{(tmp_path / 'cache.db').as_posix()}")
    session = db_module.SessionLocal()
    project = Project(name="p", default_git_url="https://example.com/r.git")
    session.add(project)
    session.commit()
    project_id = project.id
    session.close()

    cache = DbLlmResultCache(project_id)
    assert cache.get("k") is None
    cache.put("k", step="s", model="m", text='{"findings": []}', input_tokens=5, output_tokens=2)
    cache.put("k", step="s", model="m", text="ignored duplicate")  # first answer wins
    assert cache.get("k") == {"text": '{"findings": []}', "input_tokens": 5, "output_tokens": 2}
    assert DbLlmResultCache("other-project").get("k") is None


def test_run_real_scan_attaches_cache_unless_bypassed(agent, monkeypatch, tmp_path):
    from app.models import Project
    from app.services import agent_bridge

    captured = []
    monkeypatch.setattr(agent, "invoke_graph", lambda graph, state, **_k: captured.append(state) or {})
    monkeypatch.setattr(agent_bridge, "_load_agent_module", lambda: agent)
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    project = Project(id="proj-1", name="p", default_git_url="https://example.com/r.git")

    class FakeScan:
        llm_provider = None
        llm_model = None
        fallback_llm_provider = None
        fallback_llm_model = None
        metadata_json = {"use_llm": True}

    class BypassScan(FakeScan):
        metadata_json = {"use_llm": True, "bypass_llm_cache": True}

    for scan in (FakeScan(), BypassScan()):
        agent_bridge.run_real_scan(project=project, workspace=tmp_path, changed_paths=None, scan=scan)
    key = agent.RESULT_CACHE_USAGE_KEY
    assert captured[0]["usage"][key].project_id == "proj-1"
    assert key not in captured[1]["usage"]


# --- triage: candidate ids, merged windows, no lost candidates ----------------

def _hits(*pairs):
    return [{"rule": rule, "line": line, "matched_text": f"m{line}", "severity": "HIGH"}
            for rule, line in pairs]


def test_triage_prompt_merges_windows_and_lists_rules_once(lfs, rules):
    source = "\n".join(f"line{i}" for i in range(1, 61))
    hits = _hits(("secret-password-assign", 10), ("secret-password-assign", 14),
                 ("secret-password-assign", 14), ("secret-password-assign", 50))
    system, user = lfs.build_triage_prompts(
        file_path="a.py", source_text=source, hits=hits,
        rules_by_id={r.id: r for r in rules},
    )
    assert user.count("line12\n") + user.count("line12 ") == 1  # overlapping windows sent once
    assert "--- lines 1-24 ---" in user and "--- lines 40-60 ---" in user
    assert user.count("c3 |") == 1 and "c4 |" not in user  # duplicate (rule, line) collapsed
    assert "<-- c2" in user
    assert user.count("- secret-password-assign |") == 1  # rule description listed once
    assert '{"decisions": [' in system


def test_triage_missing_decision_retries_subset_then_stays_unverified(tmp_path, lfs, rules):
    source = "password = 'a'\n" + "\n" * 40 + "password = 'b'\n"
    hits = _hits(("secret-password-assign", 1), ("secret-password-assign", 42))
    prompts = []

    def fake(system, user, **kwargs):
        prompts.append(user)
        if len(prompts) == 1:
            return json.dumps({"decisions": [
                {"id": "c1", "verdict": "true_positive", "confidence": 0.9,
                 "verdict_reason": "literal secret"},
                {"id": "c9", "verdict": "true_positive", "verdict_reason": "invented"},
            ]})
        return '{"decisions": []}'

    result = lfs.triage_regex_hits(
        file_path="a.py", source_text=source, hits=hits, rules=rules, call_llm_fn=fake,
    )
    assert len(prompts) == 2
    assert "c2 |" in prompts[1] and "c1 |" not in prompts[1]  # retry carries only the gap
    by_line = {f["line"]: f for f in result["findings"]}
    assert set(by_line) == {1, 42}
    assert by_line[1]["verdict"] == "true_positive"
    assert by_line[1]["cwe"] and by_line[1]["matched_text"] == "m1"  # filled locally
    assert by_line[42]["verdict"] == "unverified"
    assert result["unverified_count"] == 1
    assert any("left unverified" in e for e in result["chunk_errors"])


def test_triage_unrecognised_verdict_is_not_a_dismissal(lfs, rules):
    hits = _hits(("secret-password-assign", 1))

    def fake(system, user, **kwargs):
        return '{"decisions": [{"id": "c1", "verdict": "maybe"}]}'

    result = lfs.triage_regex_hits(
        file_path="a.py", source_text="password = 'a'\n", hits=hits, rules=rules, call_llm_fn=fake,
    )
    assert [f["verdict"] for f in result["findings"]] == ["unverified"]


def test_triage_call_failure_keeps_every_candidate(lfs, rules):
    hits = _hits(("secret-password-assign", 1), ("secret-password-assign", 30))

    def boom(*_a, **_k):
        raise RuntimeError("throttled")

    result = lfs.triage_regex_hits(
        file_path="a.py", source_text="\n".join(["password = 'a'"] * 30), hits=hits,
        rules=rules, call_llm_fn=boom,
    )
    assert len(result["findings"]) == 2
    assert all(f["verdict"] == "unverified" for f in result["findings"])


# --- flows: shared hops sent once -----------------------------------------------

def _hop(cg, file, method, start, body, role, line=None):
    return cg.FlowHop(file=file, method=method, fqcn=f"x.{method}", name=method,
                      line=line or start + 1, start_line=start,
                      end_line=start + len(body.splitlines()) - 1, body=body, role=role,
                      label=method)


def _flow(cg, *hops):
    return cg.Flow(hops=list(hops), entry_tier="http", sink_kind="sql", authenticated=False,
                   files=sorted({h.file for h in hops}))


def test_flows_sharing_a_sink_hop_are_verified_in_one_call(fv, cg):
    sink = _hop(cg, "Dao.java", "query", 10, "query(String id) {\n  SHARED_SINK_BODY(id);\n}", "sink", 11)
    flow_a = _flow(cg, _hop(cg, "A.java", "a", 1, "a(String id) {\n  dao.query(id);\n}", "entry"), sink)
    flow_b = _flow(cg, _hop(cg, "B.java", "b", 1, "b(String id) {\n  dao.query(id);\n}", "entry"), sink)
    prompts = []

    def fake(system, user, **kwargs):
        prompts.append(user)
        return json.dumps({"findings": [{
            "flow_id": "F2", "verdict": "true_positive", "cwe": "CWE-89", "line": 11,
            "title": "SQLi", "verdict_reason": "concatenated", "confidence": 0.9,
        }]})

    result = fv.verify_flows([flow_a, flow_b], call_llm_fn=fake)
    assert len(prompts) == 1 and result["llm_calls"] == 1
    assert prompts[0].count("SHARED_SINK_BODY") == 1
    assert result["flows_verified"] == 2
    tp_by_entry = {r["flow"]["hops"][0]["method"]: r["tp_count"] for r in result["files"]}
    assert tp_by_entry == {"a": 0, "b": 1}  # attributed by flow_id


def test_unrelated_flows_are_not_batched(fv, cg):
    flow_a = _flow(cg, _hop(cg, "A.java", "a", 1, "a() {}", "entry"), _hop(cg, "D1.java", "q1", 1, "q1() {}", "sink"))
    flow_b = _flow(cg, _hop(cg, "B.java", "b", 1, "b() {}", "entry"), _hop(cg, "D2.java", "q2", 1, "q2() {}", "sink"))
    calls = []
    result = fv.verify_flows([flow_a, flow_b], call_llm_fn=lambda s, u, **k: calls.append(u) or '{"findings": []}')
    assert len(calls) == 2 and result["llm_calls"] == 2


def test_unparseable_flow_response_is_failed_not_verified(fv, cg):
    flow = _flow(cg, _hop(cg, "A.java", "a", 1, "a() {}", "entry"), _hop(cg, "D.java", "q", 1, "q() {}", "sink"))
    result = fv.verify_flows([flow], call_llm_fn=lambda s, u, **k: "garbage")
    assert result["flows_verified"] == 0 and result["flows_failed"] == 1


def test_oversized_slice_condenses_only_intermediate_hops(fv, cg, monkeypatch):
    monkeypatch.setattr(fv, "FLOW_SLICE_CHAR_BUDGET", 200)
    middle_body = "\n".join(["m(String id) {"] + [f"  filler{i}();" for i in range(60)]
                            + ["  next(id);"] + ["}"])
    entry = _hop(cg, "A.java", "a", 1, "a(String id) {\n  ENTRY_WHOLE(id);\n}", "entry")
    middle = _hop(cg, "M.java", "m", 100, middle_body, "hop", line=161)
    sink = _hop(cg, "D.java", "q", 1, "q(String id) {\n  SINK_WHOLE(id);\n}", "sink")
    text = fv.build_flow_slice(_flow(cg, entry, middle, sink))
    assert "ENTRY_WHOLE" in text and "SINK_WHOLE" in text
    assert "161:   next(id);" in text and "100: m(String id) {" in text
    assert "filler5()" not in text and "condensed" in text


# --- prompt-cache warm-up gate ------------------------------------------------

class _TimedBedrock:
    """Records when each invoke starts/ends and how many overlap."""

    def __init__(self, delay=0.05, fail_first=False):
        import threading

        self.delay = delay
        self.fail_first = fail_first
        self.calls = []  # (start, end)
        self.active = 0
        self.max_active_after_first = 0
        self._lock = threading.Lock()

    def invoke_model(self, **kwargs):
        import time

        with self._lock:
            index = len(self.calls)
            self.calls.append([time.monotonic(), None])
            self.active += 1
            if index > 0:
                self.max_active_after_first = max(self.max_active_after_first, self.active)
        time.sleep(self.delay)
        try:
            if self.fail_first and index == 0:
                raise RuntimeError("throttled")
            payload = {"content": [{"text": '"findings": []}'}],
                       "usage": {"input_tokens": 5, "output_tokens": 2}, "stop_reason": "end_turn"}
            return {"body": io.BytesIO(json.dumps(payload).encode())}
        finally:
            with self._lock:
                self.calls[index][1] = time.monotonic()
                self.active -= 1


def _fan_out(llm, n=6):
    from concurrent.futures import ThreadPoolExecutor

    system = "rule text " * 2000  # large enough to be cacheable
    with ThreadPoolExecutor(max_workers=n) as pool:
        list(pool.map(
            lambda i: llm.call_llm(system, f"user {i}", usage=llm.init_usage(), step="t",
                                   json_mode=True, retries=1),
            range(n),
        ))


@pytest.fixture()
def fresh_gates(llm):
    llm._WARM_GATES.clear()
    yield
    llm._WARM_GATES.clear()


def test_first_cacheable_call_runs_alone_then_followers_run_in_parallel(llm, monkeypatch, fresh_gates):
    fake = _TimedBedrock()
    monkeypatch.setattr(llm, "_bedrock", fake)
    _fan_out(llm)
    assert len(fake.calls) == 6
    first_end = fake.calls[0][1]
    # Nobody else started until the warming call returned...
    assert all(start >= first_end - 1e-6 for start, _end in fake.calls[1:])
    # ...and the followers were not serialized behind each other.
    assert fake.max_active_after_first > 1


def test_failed_warming_call_hands_the_gate_to_the_next_worker(llm, monkeypatch, fresh_gates):
    fake = _TimedBedrock(fail_first=True)
    monkeypatch.setattr(llm, "_bedrock", fake)
    from concurrent.futures import ThreadPoolExecutor

    system = "rule text " * 2000
    results = []

    def one(i):
        try:
            llm.call_llm(system, f"u{i}", usage=llm.init_usage(), step="t", json_mode=True, retries=1)
            results.append("ok")
        except Exception:
            results.append("err")

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(one, range(4)))
    assert results.count("err") == 1 and results.count("ok") == 3  # no deadlock, gate not stuck cold
    assert len(llm._WARM_GATES) == 1 and next(iter(llm._WARM_GATES.values())).is_warm()


def test_warm_gate_rearms_after_cache_ttl(llm, monkeypatch, fresh_gates):
    fake = _TimedBedrock(delay=0.01)
    monkeypatch.setattr(llm, "_bedrock", fake)
    _fan_out(llm, n=1)
    gate = next(iter(llm._WARM_GATES.values()))
    assert gate.is_warm()
    gate.warmed_at -= llm.PROMPT_CACHE_WARM_TTL_SECONDS + 1
    assert not gate.is_warm()


def test_small_system_prompts_skip_the_gate(llm, monkeypatch, fresh_gates):
    fake = _TimedBedrock(delay=0.02)
    monkeypatch.setattr(llm, "_bedrock", fake)
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda i: llm.call_llm("tiny", f"u{i}", usage=llm.init_usage(), step="t",
                                             json_mode=True, retries=1), range(4)))
    assert llm._WARM_GATES == {} and fake.max_active_after_first > 1


# --- rule derivation fits its output ceiling ------------------------------------

def test_derive_rules_asks_for_a_number_that_fits_and_sizes_the_ceiling(agent):
    dr = sys.modules["pipeline.derive_rules"]
    seen = {}

    def fake(system, user, **kwargs):
        seen["user"], seen["max_tokens"] = user, kwargs.get("max_tokens")
        return '{"rules": []}'

    dr.llm_derive_rules(
        stack_context="Java", frameworks=[], surfaces=[], catalog_ids=[], pass_a_names=[],
        sample_types=[], remaining_slots=50, call_llm_fn=fake,
    )
    assert f"Return at most {dr.PASS_B_MAX_RULES_PER_CALL} objects" in seen["user"]
    expected = dr.PASS_B_MAX_RULES_PER_CALL * dr.PASS_B_TOKENS_PER_RULE + dr.PASS_B_TOKEN_HEADROOM
    assert seen["max_tokens"] == expected > 4096  # the old ceiling that truncated every scan

    dr.llm_derive_rules(
        stack_context="Java", frameworks=[], surfaces=[], catalog_ids=[], pass_a_names=[],
        sample_types=[], remaining_slots=5, call_llm_fn=fake,
    )
    assert "Return at most 5 objects" in seen["user"]
    assert seen["max_tokens"] == 5 * dr.PASS_B_TOKENS_PER_RULE + dr.PASS_B_TOKEN_HEADROOM
