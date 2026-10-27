"""Strict verdict parsing (SAST-00-020): a missing, malformed or unrecognised
LLM verdict is recorded as unresolved with its reason, never as a dismissal."""

import json
import re
import sys
from pathlib import Path

import pytest

pytest.importorskip("langgraph")

from app import db as db_module  # noqa: E402
from app.config import settings  # noqa: E402
from app.db import init_db  # noqa: E402
from app.models import Finding, Project, Scan  # noqa: E402
from app.services.agent_bridge import _load_agent_module  # noqa: E402
from app.services.scan_runner import _make_findings_writer  # noqa: E402

_ENGINE_DIR = Path(__file__).resolve().parents[1] / "sast_engine"
_RESPONSES = Path(__file__).parent / "fixtures" / "llm_responses" / "verdicts"

MISSING = "llm_missing_verdict"
UNRECOGNISED = "llm_unrecognised_verdict"


@pytest.fixture()
def agent(monkeypatch):
    monkeypatch.setattr(settings, "sast_framework_path", str(_ENGINE_DIR))
    sys.modules.pop("sast_scan_agent", None)
    return _load_agent_module()


@pytest.fixture()
def lfs(agent):
    return sys.modules["pipeline.llm_file_scan"]


@pytest.fixture()
def llm_client(agent):
    return sys.modules["llm_client"]


@pytest.fixture()
def rules(agent):
    return sys.modules["pipeline.regex_scan"].load_rules(_ENGINE_DIR / "rules")


def _canned(name: str) -> str:
    return (_RESPONSES / name).read_text(encoding="utf-8")


# --- the parser -------------------------------------------------------------

PARSE_TABLE = [
    # exact enums, case-insensitive, `-` read as `_`
    ("true_positive", ("true_positive", None)),
    ("TRUE_POSITIVE", ("true_positive", None)),
    ("true-positive", ("true_positive", None)),
    ("  True_Positive  ", ("true_positive", None)),
    ("false_positive", ("false_positive", None)),
    ("FALSE-POSITIVE", ("false_positive", None)),
    # the fixed alias table
    ("tp", ("true_positive", None)),
    ("TP", ("true_positive", None)),
    ("fp", ("false_positive", None)),
    ("True Positive", ("true_positive", None)),
    ("False Positive", ("false_positive", None)),
    ("false  positive", ("false_positive", None)),
    ("confirmed", ("true_positive", None)),
    ("Dismissed", ("false_positive", None)),
    # a literal unverified is an answer, but an undecided one
    ("unverified", ("unverified", "evidence_missing")),
    # ambiguity must never dismiss (these all used to become false_positive)
    ("not sure", (None, UNRECOGNISED)),
    ("no decision", (None, UNRECOGNISED)),
    ("cannot determine", (None, UNRECOGNISED)),
    ("unknown", (None, UNRECOGNISED)),
    ("maybe", (None, UNRECOGNISED)),
    ("possibly", (None, UNRECOGNISED)),
    ("n/a", (None, UNRECOGNISED)),
    ("needs_review", (None, UNRECOGNISED)),
    ("not a true positive", (None, UNRECOGNISED)),
    ("not-a-true-positive", (None, UNRECOGNISED)),
    ("NOT_TRUE_POSITIVE", (None, UNRECOGNISED)),
    # and these all used to become true_positive
    ("unconfirmed", (None, UNRECOGNISED)),
    ("true positive?", (None, UNRECOGNISED)),
    ("is not false positive", (None, UNRECOGNISED)),
    # nothing usable at all
    ("", (None, MISSING)),
    ("   ", (None, MISSING)),
    (None, (None, MISSING)),
    # not a string
    (42, (None, UNRECOGNISED)),
    (True, (None, UNRECOGNISED)),
    (["true_positive"], (None, UNRECOGNISED)),
    ({"verdict": "true_positive"}, (None, UNRECOGNISED)),
]


@pytest.mark.parametrize("raw,expected", PARSE_TABLE, ids=[repr(r) for r, _ in PARSE_TABLE])
def test_parse_verdict_table(lfs, raw, expected):
    assert lfs.parse_verdict(raw) == expected


def test_the_table_is_broad_enough():
    assert len(PARSE_TABLE) >= 25


def test_the_old_lenient_parsers_are_gone():
    leftovers = []
    for path in _ENGINE_DIR.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if re.search(r"_normalize_verdict|_strict_verdict|_NEGATION_RE", text):
            leftovers.append(str(path.relative_to(_ENGINE_DIR)))
    assert leftovers == []


# --- confidence -------------------------------------------------------------

def test_an_unresolved_verdict_has_no_invented_confidence(lfs):
    assert lfs._normalize_confidence(None, None) is None
    assert lfs._normalize_confidence(0.9, "unverified") is None
    # A decided verdict with no stated confidence keeps its old defaults.
    assert lfs._normalize_confidence(None, "true_positive") == 0.7
    assert lfs._normalize_confidence(None, "false_positive") == 0.5
    assert lfs._normalize_confidence(85, "true_positive") == 0.85


# --- deep scan ---------------------------------------------------------------

def _chunk(text="x = 1\npassword = 'hunter2'\neval(x)\n"):
    return {"start_line": 1, "end_line": len(text.splitlines()), "text": text}


def test_a_deep_scan_finding_with_an_unrecognised_verdict_is_unresolved(lfs, llm_client):
    usage = {}
    result = lfs.scan_chunk(
        file_path="a.py", chunk=_chunk(), catalog=[], stack_context="",
        usage=usage, call_llm_fn=lambda *a, **k: _canned("deep_scan_possibly.json"),
    )
    (finding,) = result["findings"]
    assert finding["verdict"] == "unverified"
    assert finding["unresolved_reason"] == UNRECOGNISED
    assert finding["confidence"] is None
    assert "possibly" in finding["verdict_reason"]
    assert usage["verdict_stats"]["scan_deep_files"] == {"unrecognised_verdicts": 1}


def test_the_raw_text_in_the_reason_is_bounded(lfs):
    raw = {"line": 1, "verdict": "p" * 500, "rule_id": "x", "cwe": "CWE-1", "title": "t"}
    finding = lfs.normalize_finding(raw, file_path="a.py", chunk_start=1, chunk_end=3)
    assert finding["verdict"] == "unverified"
    assert len(finding["verdict_reason"]) < 300


def test_missing_and_unrecognised_verdicts_are_counted_per_step(lfs, llm_client):
    usage = {}
    result = lfs.scan_chunk(
        file_path="a.py", chunk=_chunk(), catalog=[], stack_context="",
        usage=usage, call_llm_fn=lambda *a, **k: _canned("deep_scan_mixed.json"),
    )
    by_line = {f["line"]: f for f in result["findings"]}
    assert by_line[1]["verdict"] == "true_positive"
    assert by_line[2]["unresolved_reason"] == MISSING
    assert by_line[3]["unresolved_reason"] == UNRECOGNISED
    summary = llm_client.usage_cost_summary(usage)
    assert summary["by_step"]["scan_deep_files"]["missing_verdicts"] == 1
    assert summary["by_step"]["scan_deep_files"]["unrecognised_verdicts"] == 1
    assert summary["missing_verdicts"] == 1 and summary["unrecognised_verdicts"] == 1


def test_an_unresolved_deep_scan_finding_is_persisted_unverified(lfs, tmp_path):
    SessionLocal = init_db(f"sqlite:///{(tmp_path / 'p.db').as_posix()}")
    with SessionLocal() as db:
        project = Project(name="verdicts", default_git_url="https://github.com/org/repo.git")
        db.add(project)
        db.commit()
        scan = Scan(project_id=project.id, git_url=project.default_git_url)
        db.add(scan)
        db.commit()
        scan_id = scan.id
    result = lfs.scan_chunk(
        file_path="a.py", chunk=_chunk(), catalog=[], stack_context="",
        call_llm_fn=lambda *a, **k: _canned("deep_scan_possibly.json"),
    )
    _make_findings_writer(scan_id)("a.py", result["findings"])
    with db_module.SessionLocal() as db:
        row = db.query(Finding).filter(Finding.scan_id == scan_id).one()
    assert (row.verdict, row.unresolved_reason, row.confidence) == ("unverified", UNRECOGNISED, None)


def test_unverified_deep_scan_findings_survive_every_publish_filter(lfs):
    finding = lfs.normalize_finding(
        {"line": 1, "verdict": "maybe", "rule_id": "secret-password-assign", "cwe": "CWE-798",
         "title": "t", "severity": "HIGH"},
        file_path="a.py", chunk_start=1, chunk_end=3,
    )
    assert lfs.should_publish_finding(
        finding, "password = 'x'", suppress_no_cwe=True, suppress_http_findings=True,
        suppress_low_confidence_false_positives=True,
    )


def test_an_unverified_finding_on_a_noisy_sql_rule_is_not_dropped(lfs):
    noisy = next(iter(sys.modules["pipeline.regex_scan"]._SQL_CONCAT_CATALOG_IDS))
    finding = lfs.normalize_finding(
        {"line": 1, "verdict": "maybe", "rule_id": noisy, "cwe": "CWE-89", "title": "sqli"},
        file_path="A.java", chunk_start=1, chunk_end=3,
    )
    assert lfs.should_publish_finding(finding, "no query construction here")
    dismissed = dict(finding, verdict="false_positive", confidence=0.9)
    assert not lfs.should_publish_finding(dismissed, "no query construction here")


def test_merging_duplicates_keeps_an_undecided_answer_over_a_dismissal(lfs):
    base = {"line": 5, "severity": "HIGH", "rule_id": "r", "cwe": "CWE-89", "title": "sqli"}
    undecided = dict(base, verdict="unverified", confidence=None)
    dismissed = dict(base, verdict="false_positive", confidence=0.9)
    confirmed = dict(base, verdict="true_positive", confidence=0.4)
    assert lfs.merge_dedupe([dismissed, undecided])[0]["verdict"] == "unverified"
    assert lfs.merge_dedupe([undecided, dismissed])[0]["verdict"] == "unverified"
    assert lfs.merge_dedupe([undecided, confirmed])[0]["verdict"] == "true_positive"


def test_file_tallies_count_unverified_separately(lfs, tmp_path):
    (tmp_path / "a.py").write_text("x = 1\npassword = 'hunter2'\neval(x)\n", encoding="utf-8")
    result = lfs.scan_file(
        repo_root=tmp_path, rel_path="a.py", rules=[],
        call_llm_fn=lambda *a, **k: _canned("deep_scan_mixed.json"), chunk_workers=1,
    )
    assert (result["tp_count"], result["fp_count"], result["unverified_count"]) == (1, 0, 2)


# --- group confirmation -----------------------------------------------------

def _unverified(path, matched):
    return {
        "rule_id": "secret-password-assign", "title": "hardcoded password", "severity": "MEDIUM",
        "cwe": "CWE-798", "owasp_category": "A07:2021-Identification-and-Authentication-Failures",
        "line": 1, "snippet": matched, "matched_text": matched, "verdict": "unverified",
        "unresolved_reason": "not_reviewed_regex", "kind": "regex", "confidence": None,
        "file_path": path,
    }


def test_a_batch_group_with_an_unrecognised_verdict_stays_unverified(lfs, rules, tmp_path):
    names = ("a.py", "b.py", "c.py")
    for name in names:
        (tmp_path / name).write_text(f"password = '{name}'\n", encoding="utf-8")
    results = [
        {"file_path": name, "findings": [_unverified(name, f"password = '{name}'")]} for name in names
    ]
    usage = {}

    lfs.group_confirm_unverified_findings(
        file_results=results, repo_root=tmp_path, rules=rules, usage=usage, group_workers=1,
        groups_per_call=3, call_llm_fn=lambda *a, **k: _canned("group_batch_mixed.json"),
    )

    verdicts = {r["file_path"]: r["findings"][0] for r in results}
    # Groups are confirmed in occurrence order; with equal sizes that is first-seen.
    assert [verdicts[n]["verdict"] for n in names] == ["true_positive", "unverified", "false_positive"]
    assert verdicts["b.py"]["unresolved_reason"] == UNRECOGNISED
    assert verdicts["a.py"]["unresolved_reason"] is None
    assert usage["verdict_stats"]["group_confirm_triage_findings"] == {"unrecognised_verdicts": 1}


def test_a_group_confirm_item_with_no_verdict_is_missing_not_dismissed(lfs):
    result = lfs._confirm_result_from_item({"confidence": 0.5})
    assert result["verdict"] == "unverified"
    assert result["unresolved_reason"] == MISSING
    assert result["error"]


# --- triage -----------------------------------------------------------------

def test_triage_records_why_a_candidate_stayed_undecided(lfs, rules):
    hits = [{"rule": "secret-password-assign", "line": 1, "matched_text": "password = 'a'",
             "severity": "HIGH"}]
    usage = {}
    result = lfs.triage_regex_hits(
        file_path="a.py", source_text="password = 'a'\n", hits=hits, rules=rules, usage=usage,
        call_llm_fn=lambda *a, **k: '{"decisions": [{"id": "c1", "verdict": "maybe"}]}',
    )
    (finding,) = result["findings"]
    assert finding["verdict"] == "unverified"
    assert finding["unresolved_reason"] == UNRECOGNISED
    assert "maybe" in finding["verdict_reason"]
    assert usage["verdict_stats"]["scan_triage_files"] == {"unrecognised_verdicts": 1}


def test_triage_aliases_are_accepted(lfs, rules):
    hits = [{"rule": "secret-password-assign", "line": 1, "matched_text": "password = 'a'",
             "severity": "HIGH"}]
    result = lfs.triage_regex_hits(
        file_path="a.py", source_text="password = 'a'\n", hits=hits, rules=rules,
        call_llm_fn=lambda *a, **k: (
            '{"decisions": [{"id": "c1", "verdict": "fp", "verdict_reason": "fixture"}]}'
        ),
    )
    assert [f["verdict"] for f in result["findings"]] == ["false_positive"]


# --- flow verification ------------------------------------------------------

def test_flow_verify_shares_the_strict_parser(agent):
    assert sys.modules["pipeline.flow_verify"].normalize_finding is sys.modules[
        "pipeline.llm_file_scan"
    ].normalize_finding


def test_flow_verify_leaves_an_unrecognised_verdict_unresolved(agent, tmp_path):
    pytest.importorskip("tree_sitter_java")
    from tests.test_flow_verify import CONTROLLER, DAO, SERVICE, _write

    cg = sys.modules["pipeline.call_graph"]
    fv = sys.modules["pipeline.flow_verify"]
    base = "src/main/java/com/example/"
    for name, source in (("FooController", CONTROLLER), ("FooService", SERVICE), ("FooDao", DAO)):
        _write(tmp_path, f"{base}{name}.java", source)
    flows = cg.discover_flows(cg.build_call_graph(
        tmp_path, [f"{base}{n}.java" for n in ("FooController", "FooService", "FooDao")]
    ))
    payload = [{
        "verdict": "kind of", "severity": "HIGH", "cwe": "CWE-89", "rule_id": "llm-extra",
        "title": "SQL injection", "line": flows[0].hops[-1].line, "confidence": 0.9,
        "source": "id", "sink": "executeQuery", "data_flow": "id -> executeQuery",
    }]
    usage = {}
    written = []

    result = fv.verify_flows(
        flows, call_llm_fn=lambda *a, **k: json.dumps(payload), usage=usage,
        findings_writer=lambda path, findings: written.append(findings),
    )

    (finding,) = written[0]
    assert finding["verdict"] == "unverified"
    assert finding["unresolved_reason"] == UNRECOGNISED
    assert finding["confidence"] is None
    assert (result["tp_count"], result["fp_count"]) == (0, 0)
    assert usage["verdict_stats"]["verify_flow_slices"] == {"unrecognised_verdicts": 1}


# --- result cache -----------------------------------------------------------

def test_the_result_cache_key_changes_with_the_cache_version(llm_client, monkeypatch):
    assert llm_client.RESULT_CACHE_VERSION == "5"
    args = ("system", "user")
    kwargs = dict(provider="bedrock", model="m", max_tokens=100, temperature=0.0, json_mode=True)
    current = llm_client.result_cache_key(*args, **kwargs)
    monkeypatch.setattr(llm_client, "RESULT_CACHE_VERSION", "1")
    assert llm_client.result_cache_key(*args, **kwargs) != current
