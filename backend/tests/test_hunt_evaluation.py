"""Benchmark scoring for the agentic hunt.

Offline: the scoring functions on synthetic data.
Live (`pytest -m live tests/test_hunt_evaluation.py`): runs the real engine —
catalog-only, then catalog + hunt — over a local OWASP Benchmark Java checkout
and prints/asserts the scorecard comparison. Configure with:

  HUNT_BENCHMARK_DIR   path to a BenchmarkJava checkout (contains expectedresults-*.csv)
  HUNT_LLM_PROVIDER    bedrock | openai_compat (default bedrock)
  HUNT_LLM_MODEL       model id
  HUNT_LLM_BASE_URL    for openai_compat
  HUNT_BUDGET_USD      hunt ceiling (default 5)
  HUNT_MAX_HYPOTHESES  default 20
"""

import json
import os
import sys
from pathlib import Path

import pytest

pytest.importorskip("boto3", reason="pipeline modules import llm_client")

_ENGINE_DIR = Path(__file__).resolve().parents[1] / "sast_engine"
if str(_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(_ENGINE_DIR))

from pipeline.hunt.evaluation import (  # noqa: E402
    compare,
    enclosing_method_name,
    load_benchmark_expected,
    score_juliet,
    score_owasp_benchmark,
)


def test_owasp_benchmark_scoring(tmp_path):
    csv_path = tmp_path / "expectedresults-1.2.csv"
    csv_path.write_text(
        "# test name, category, real vulnerability, cwe, Benchmark version: 1.2, 2016-06-1\n"
        "BenchmarkTest00001,pathtraver,true,22\n"
        "BenchmarkTest00002,pathtraver,false,22\n"
        "BenchmarkTest00003,sqli,true,89\n"
        "BenchmarkTest00004,sqli,false,89\n",
        encoding="utf-8",
    )
    expected = load_benchmark_expected(csv_path)
    findings = [
        {"file_path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java", "cwe": "CWE-23", "verdict": "true_positive"},
        {"file_path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00004.java", "cwe": "CWE-89", "verdict": "unverified"},
        # Wrong CWE family for the case: does not count.
        {"file_path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00003.java", "cwe": "CWE-79", "verdict": "true_positive"},
        # Dismissed findings never count as flagged.
        {"file_path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00002.java", "cwe": "CWE-22", "verdict": "false_positive"},
    ]
    scores = score_owasp_benchmark(findings, expected)
    assert scores["categories"]["pathtraver"] == {"tp": 1, "fn": 0, "fp": 0, "tn": 1, "tpr": 1.0, "fpr": 0.0, "score": 1.0}
    assert scores["categories"]["sqli"]["fp"] == 1 and scores["categories"]["sqli"]["fn"] == 1
    # pathtraver scores 1.0 and sqli 0.0 - 1.0 = -1.0, so the mean is 0.0.
    assert scores["average_score"] == 0.0


def test_owasp_benchmark_average_is_mean_of_category_youden_scores(tmp_path):
    csv_path = tmp_path / "expected.csv"
    csv_path.write_text(
        "BenchmarkTest00001,cmdi,true,78\nBenchmarkTest00002,cmdi,false,78\n"
        "BenchmarkTest00003,xss,true,79\nBenchmarkTest00004,xss,false,79\n",
        encoding="utf-8",
    )
    findings = [
        {"file_path": "x/BenchmarkTest00001.java", "cwe": "CWE-78", "verdict": "true_positive"},
        {"file_path": "x/BenchmarkTest00003.java", "cwe": "CWE-79", "verdict": "true_positive"},
        {"file_path": "x/BenchmarkTest00004.java", "cwe": "CWE-79", "verdict": "true_positive"},
    ]
    scores = score_owasp_benchmark(findings, load_benchmark_expected(csv_path))
    assert scores["categories"]["cmdi"]["score"] == 1.0
    assert scores["categories"]["xss"]["score"] == 0.0
    assert scores["average_score"] == 0.5
    baseline = score_owasp_benchmark(findings[:1], load_benchmark_expected(csv_path))
    delta = compare(baseline, scores)
    assert delta["tp_gained"] == 1 and delta["fp_gained"] == 1


def test_juliet_scoring_by_bad_and_good_methods(tmp_path):
    case = tmp_path / "testcases" / "CWE89_SQL_Injection"
    case.mkdir(parents=True)
    (case / "CWE89_SQL_Injection__getParameter_Servlet_01.java").write_text(
        "public class X {\n"
        "    public void bad(HttpServletRequest request) throws Throwable {\n"
        "        String data = request.getParameter(\"name\");\n"
        "        stmt.execute(\"select * from t where n='\" + data + \"'\");\n"
        "    }\n"
        "    private void goodG2B(HttpServletRequest request) throws Throwable {\n"
        "        String data = \"foo\";\n"
        "        stmt.execute(\"select * from t where n='\" + data + \"'\");\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    rel = "testcases/CWE89_SQL_Injection/CWE89_SQL_Injection__getParameter_Servlet_01.java"
    lines = (tmp_path / rel).read_text().splitlines()
    assert enclosing_method_name(lines, 4) == "bad"
    assert enclosing_method_name(lines, 8) == "goodG2B"

    only_bad = score_juliet([{"file_path": rel, "line": 4, "cwe": "CWE-89", "verdict": "true_positive"}], tmp_path)
    assert only_bad["categories"]["CWE-89"] == {"tp": 1, "fn": 0, "fp": 0, "tn": 1, "tpr": 1.0, "fpr": 0.0, "score": 1.0}
    both = score_juliet([
        {"file_path": rel, "line": 4, "cwe": "CWE-89", "verdict": "true_positive"},
        {"file_path": rel, "line": 8, "cwe": "CWE-89", "verdict": "unverified"},
    ], tmp_path)
    assert both["categories"]["CWE-89"]["fp"] == 1


# --- live --------------------------------------------------------------------


@pytest.mark.live
def test_live_owasp_benchmark_catalog_vs_hunt(monkeypatch, tmp_path):
    bench = os.environ.get("HUNT_BENCHMARK_DIR")
    if not bench or not Path(bench).is_dir():
        pytest.skip("set HUNT_BENCHMARK_DIR to an OWASP BenchmarkJava checkout")
    expected_csv = sorted(Path(bench).glob("expectedresults-*.csv"))
    if not expected_csv:
        pytest.skip("no expectedresults-*.csv in HUNT_BENCHMARK_DIR")
    from app.config import settings
    from app.services.agent_bridge import _load_agent_module
    from pipeline.hunt.evaluation import findings_from_report_files

    monkeypatch.setattr(settings, "sast_framework_path", str(_ENGINE_DIR))
    sys.modules.pop("sast_scan_agent", None)
    agent = _load_agent_module()
    provider = os.environ.get("HUNT_LLM_PROVIDER", "bedrock")
    options = {"openai_compat": {"base_url": os.environ["HUNT_LLM_BASE_URL"]}} if os.environ.get("HUNT_LLM_BASE_URL") else None
    usage = agent.init_usage(provider, os.environ.get("HUNT_LLM_MODEL"), provider_options=options)
    state = {
        "local_path": bench, "scope": None, "context_note": "", "verbose": True, "verbose_files": False,
        "persist_to_disk": False, "use_llm": True, "_tracer": agent.AgentTrace(verbose=True), "usage": usage,
        "llm_provider": provider, "llm_model": os.environ.get("HUNT_LLM_MODEL"),
        "triage_mode": "regex_only", "deep_scan_file_cap": 0, "confirm_triage_groups": False,
        "hunt_mode": "agentic", "hunt_profile": "benchmark",
        "hunt_budget_usd": float(os.environ.get("HUNT_BUDGET_USD", "5")),
        "hunt_max_hypotheses": int(os.environ.get("HUNT_MAX_HYPOTHESES", "20")),
    }
    final = agent.invoke_graph(agent.build_graph(), state)
    expected = load_benchmark_expected(expected_csv[-1])
    catalog = findings_from_report_files((final.get("triage_scan_results") or {}).get("files") or [])
    hunt = findings_from_report_files((final.get("hunt_scan_results") or {}).get("files") or [])
    baseline = score_owasp_benchmark(catalog, expected)
    combined = score_owasp_benchmark(catalog + hunt, expected)
    hunt_only_tp = score_owasp_benchmark(hunt, expected, verdicts=("true_positive",))
    summary = {
        "catalog": baseline["overall"], "catalog_plus_hunt": combined["overall"],
        "hunt_confirmed_only": hunt_only_tp["overall"], "delta": compare(baseline, combined),
        "hunt": {k: v for k, v in (final.get("hunt_scan_results") or {}).items() if k not in ("files", "hypotheses")},
    }
    (tmp_path / "benchmark_scorecard.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    # Acceptance gates from the plan: the hunt must add recall without
    # raising the false-positive rate of what it confirms.
    assert summary["delta"]["tp_gained"] >= 0
    assert hunt_only_tp["overall"]["fpr"] <= baseline["overall"]["fpr"] + 0.05
