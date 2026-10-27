"""Per-member grouped confirmation with coverage accounting (SAST-01-070)."""

import json
import re
import sys
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("boto3", reason="pipeline modules import llm_client")

_ENGINE = Path(__file__).resolve().parents[1] / "sast_engine"
if str(_ENGINE) not in sys.path:
    sys.path.insert(0, str(_ENGINE))

from llm_client import LlmBudgetExhausted  # noqa: E402
from pipeline import llm_file_scan as lfs  # noqa: E402

pytestmark = pytest.mark.unit

RULE = "secret-password-assign"


def _member(i, text_lines=None):
    return {
        "rule_id": RULE, "title": "hardcoded password", "severity": "MEDIUM", "cwe": "CWE-798",
        "owasp_category": "A07:2021-Identification-and-Authentication-Failures",
        "line": 3, "snippet": "x", "matched_text": "password = 'x'", "verdict": "unverified",
        "unresolved_reason": "not_reviewed_regex", "kind": "regex", "confidence": None,
        "verdict_reason": "Regex pattern match, not reviewed by an LLM — confirm before acting on it.",
        "file_path": f"src/f{i:03d}.py",
    }


def _repo(tmp_path, n, *, identical=False, width=1):
    for i in range(n):
        body = "\n".join(
            [f"# file {'same' if identical else i}", "import os", "password = 'x'"]
            + [f"filler_{k} = {k}" for k in range(width)]
        )
        path = tmp_path / "src" / f"f{i:03d}.py"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body + "\n", encoding="utf-8")


def _results(n):
    return [{"file_path": f"src/f{i:03d}.py", "findings": [_member(i)]} for i in range(n)]


class Model:
    """A fake provider: answers every occurrence id listed in the prompt, except
    those in `omit`, with the verdict `verdicts` gives for its file."""

    def __init__(self, verdicts=None, omit=(), default="true_positive", raises=None):
        self.calls = []
        self.verdicts, self.omit, self.default, self.raises = verdicts or {}, set(omit), default, raises

    def __call__(self, system, user, **kwargs):
        self.calls.append(user)
        if self.raises is not None:
            raise self.raises
        decisions = []
        for member, path in re.findall(r"^(m\d+) \| (\S+?):\d+", user, flags=re.M):
            if member in self.omit:
                continue
            decisions.append({
                "member": member, "verdict": self.verdicts.get(path, self.default),
                "confidence": 0.8, "verdict_reason": f"decided {member}",
            })
        return json.dumps({"decisions": decisions})


def _confirm(tmp_path, results, model, **kwargs):
    usage = {}
    writes = []
    out = lfs.group_confirm_unverified_findings(
        file_results=results, repo_root=tmp_path, rules=[], call_llm_fn=model, group_workers=1,
        usage=usage, verdict_updates_writer=lambda p, u: writes.append((p, u)), **kwargs,
    )
    return out, usage, writes


def _finding(results, i):
    return results[i]["findings"][0]


def test_every_member_in_budget_gets_an_excerpt_and_its_own_decision(tmp_path):
    _repo(tmp_path, 5)
    results = _results(5)
    model = Model(verdicts={"src/f002.py": "false_positive"})
    out, usage, writes = _confirm(tmp_path, results, model)
    (prompt,) = model.calls
    for n in range(1, 6):
        assert f"m{n} | src/f{n - 1:03d}.py:3" in prompt
    assert [_finding(results, i)["verdict"] for i in range(5)] == [
        "true_positive", "true_positive", "false_positive", "true_positive", "true_positive",
    ]
    assert "Reviewed 5 of 5 occurrences" in _finding(results, 0)["verdict_reason"]
    assert _finding(results, 0)["review_coverage"] == {"reviewed": 5, "total": 5}
    assert (out["members_reviewed"], out["members_total"], out["members_not_in_sample"]) == (5, 5, 0)
    assert usage["_counters"]["group_confirm_coverage"]["members_reviewed"] == 5
    update = {u["line"]: u for _p, ups in writes for u in ups if _p == "src/f002.py"}[3]
    assert update["verdict"] == "false_positive" and update["review_coverage"] == {"reviewed": 5, "total": 5}


def test_a_member_missing_from_the_response_gets_one_follow_up_for_that_member_only(tmp_path):
    _repo(tmp_path, 5)
    results = _results(5)

    class Flaky(Model):
        def __call__(self, system, user, **kwargs):
            if len(self.calls) == 0:
                self.omit = {"m4"}
            else:
                self.omit = set()
            return super().__call__(system, user, **kwargs)

    model = Flaky()
    _confirm(tmp_path, results, model)
    assert len(model.calls) == 2
    follow_up = model.calls[1]
    assert "m4 | src/f003.py:3" in follow_up
    assert "m1 |" not in follow_up and "m5 |" not in follow_up
    assert _finding(results, 3)["verdict"] == "true_positive"


def test_a_member_still_missing_after_the_follow_up_is_llm_missing_verdict(tmp_path):
    _repo(tmp_path, 5)
    results = _results(5)
    model = Model(omit={"m4"})
    out, _usage, _writes = _confirm(tmp_path, results, model)
    assert len(model.calls) == 2  # the round, and exactly one follow-up
    m4 = _finding(results, 3)
    assert m4["verdict"] == "unverified" and m4["unresolved_reason"] == "llm_missing_verdict"
    assert all(_finding(results, i)["verdict"] == "true_positive" for i in (0, 1, 2, 4))
    assert out["members_reviewed"] == 4


def test_members_over_the_budget_are_not_in_sample_and_never_inherit_a_verdict(tmp_path, monkeypatch):
    monkeypatch.setattr(lfs, "GROUP_CONFIRM_MEMBER_CHAR_BUDGET", 700)
    _repo(tmp_path, 40)
    results = _results(40)
    model = Model()
    out, usage, writes = _confirm(tmp_path, results, model)
    assert len(model.calls) == 2  # the round, and one follow-up for the members that did not fit
    verdicts = [_finding(results, i)["verdict"] for i in range(40)]
    reviewed = verdicts.count("true_positive")
    assert 0 < reviewed < 40
    not_in_sample = [f for f in (_finding(results, i) for i in range(40)) if f["verdict"] == "unverified"]
    assert len(not_in_sample) == 40 - reviewed
    assert {f["unresolved_reason"] for f in not_in_sample} == {"not_in_sample"}
    assert all(f["review_coverage"] == {"reviewed": reviewed, "total": 40} for f in not_in_sample)
    assert f"Reviewed {reviewed} of 40 occurrences" in next(
        f for f in (_finding(results, i) for i in range(40)) if f["verdict"] == "true_positive"
    )["verdict_reason"]
    assert out["members_not_in_sample"] == 40 - reviewed
    assert usage["_counters"]["group_confirm_coverage"]["members_not_in_sample"] == 40 - reviewed
    skipped_updates = [u for _p, ups in writes for u in ups if u.get("unresolved_reason") == "not_in_sample"]
    assert len(skipped_updates) == 40 - reviewed and "verdict" not in skipped_updates[0]


def test_a_uniform_group_takes_one_decision_for_all_members(tmp_path):
    _repo(tmp_path, 6, identical=True)
    results = _results(6)
    model = Model()
    out, _usage, _writes = _confirm(tmp_path, results, model)
    (prompt,) = model.calls
    assert "All 6 occurrences are identical" in prompt
    assert prompt.count("m1 | ") == 1 and "m2 |" not in prompt
    assert all(_finding(results, i)["verdict"] == "true_positive" for i in range(6))
    assert out["members_reviewed"] == 6 and out["members_not_in_sample"] == 0


def test_a_group_that_differs_in_code_is_not_uniform(tmp_path):
    _repo(tmp_path, 3)
    model = Model()
    _confirm(tmp_path, _results(3), model)
    assert "identical" not in model.calls[0] and "m3 |" in model.calls[0]


def test_budget_exhaustion_is_recorded_not_inherited(tmp_path):
    _repo(tmp_path, 3)
    results = _results(3)
    out, _usage, _writes = _confirm(tmp_path, results, Model(raises=LlmBudgetExhausted("cutoff")))
    for i in range(3):
        assert _finding(results, i)["verdict"] == "unverified"
        assert _finding(results, i)["unresolved_reason"] == "llm_budget_exhausted"
    assert out["error_group_count"] == 1


def test_a_provider_failure_is_llm_call_failed_for_every_member(tmp_path):
    _repo(tmp_path, 3)
    results = _results(3)
    _confirm(tmp_path, results, Model(raises=RuntimeError("down")))
    assert {_finding(results, i)["unresolved_reason"] for i in range(3)} == {"llm_call_failed"}


def test_a_positive_validator_fact_turns_a_model_dismissal_into_a_conflict(tmp_path):
    _repo(tmp_path, 3)
    results = _results(3)
    results[1]["findings"][0]["facts"] = {"validators": [
        {"validator": "v", "version": 1, "outcome": "positive_fact", "reason_tag": "t",
         "proof": "A string is concatenated into the statement."}]}
    _confirm(tmp_path, results, Model(default="false_positive"))
    assert _finding(results, 0)["verdict"] == "false_positive"
    conflicted = _finding(results, 1)
    assert conflicted["verdict"] == "unverified" and conflicted["unresolved_reason"] == "conflict"
    assert "A string is concatenated" in conflicted["verdict_reason"]


def test_the_prompt_lists_validator_facts_only_when_there_are_some(tmp_path):
    _repo(tmp_path, 3)
    plain = Model()
    _confirm(tmp_path, _results(3), plain)
    assert "Deterministic facts:" not in plain.calls[0]
    results = _results(3)
    results[0]["findings"][0]["facts"] = {"validators": [
        {"validator": "v", "version": 1, "outcome": "evidence_gap", "missing": "callee body not resolved"}]}
    with_gap = Model()
    _confirm(tmp_path, results, with_gap)
    # The occurrence with facts has a different signature, so it is its own group.
    carrying = [c for c in with_gap.calls if "Deterministic facts:" in c]
    assert len(carrying) == 1 and "callee body not resolved" in carrying[0] and "m1 | src/f000.py" in carrying[0]


def test_batched_groups_get_their_members_decided_and_the_gaps_followed_up(tmp_path):
    _repo(tmp_path, 5)
    results = _results(5)
    for r in results[3:]:
        r["findings"][0]["rule_id"] = "other-rule"  # the bigger group (3) is pattern 0
    calls = []

    def model(system, user, **kwargs):
        calls.append(user)
        decisions = []
        if "Pattern 0" in user:  # the batch: answer group 0 fully and group 1 not at all
            for m, _p in re.findall(r"^(m\d+) \| (\S+?):\d+", user.split("Pattern 1")[0], flags=re.M):
                decisions.append({"group_index": 0, "member": m, "verdict": "true_positive",
                                  "confidence": 0.7, "verdict_reason": "ok"})
        else:  # a follow-up for the unanswered group, on its own
            for m, _p in re.findall(r"^(m\d+) \| (\S+?):\d+", user, flags=re.M):
                decisions.append({"member": m, "verdict": "false_positive",
                                  "confidence": 0.7, "verdict_reason": "fine"})
        return json.dumps({"decisions": decisions})

    _confirm(tmp_path, results, model, groups_per_call=2)
    assert [_finding(results, i)["verdict"] for i in range(5)] == [
        "true_positive", "true_positive", "true_positive", "false_positive", "false_positive",
    ]
    assert len(calls) == 2


def test_member_ids_are_matched_exactly(tmp_path):
    _repo(tmp_path, 3)
    results = _results(3)

    def model(system, user, **kwargs):
        # An id the prompt never used, and a bare decision with no id at all.
        return json.dumps({"decisions": [
            {"member": "m9", "verdict": "true_positive", "confidence": 0.9, "verdict_reason": "x"},
            {"verdict": "true_positive", "confidence": 0.9, "verdict_reason": "x"},
        ]})

    _confirm(tmp_path, results, model)
    assert {_finding(results, i)["verdict"] for i in range(3)} == {"unverified"}


# --- explanation contradictions in a member's decision (SAST-01-090) ----------------------

def test_a_member_whose_reason_contradicts_its_verdict_is_retried_once_then_resolved(tmp_path):
    _repo(tmp_path, 3)
    results = _results(3)
    calls = []

    def model(system, user, **kwargs):
        calls.append(user)
        retry = "Deterministic facts:" in user
        decisions = []
        for member, _path in re.findall(r"^(m\d+) \| (\S+?):\d+", user, flags=re.M):
            bad = member == "m2" and not retry
            decisions.append({
                "member": member, "verdict": "true_positive", "confidence": 0.8,
                "verdict_reason": ("The query is parameterized, so there is no injection risk."
                                   if bad else "A password is assigned a literal."),
            })
        return json.dumps({"decisions": decisions})

    usage = {}
    out = lfs.group_confirm_unverified_findings(
        file_results=results, repo_root=tmp_path, rules=[], call_llm_fn=model, group_workers=1, usage=usage,
    )
    assert len(calls) == 2
    retry = calls[1]
    assert "m2:" in retry and "m1 |" not in retry and "m3 |" not in retry
    assert all(_finding(results, i)["verdict"] == "true_positive" for i in range(3))
    assert "parameterized" not in _finding(results, 1)["verdict_reason"]
    assert out["members_reviewed"] == 3
    assert usage["_counters"]["explanation_contradictions"]["retry_resolved"] == 1


def test_a_member_whose_retry_still_contradicts_is_unresolved_not_dismissed(tmp_path):
    _repo(tmp_path, 2)
    results = _results(2)

    def model(system, user, **kwargs):
        decisions = [
            {"member": member, "verdict": "false_positive", "confidence": 0.9,
             "verdict_reason": "An attacker can control this value."}
            for member, _p in re.findall(r"^(m\d+) \| (\S+?):\d+", user, flags=re.M)
        ]
        return json.dumps({"decisions": decisions})

    writes = []
    out = lfs.group_confirm_unverified_findings(
        file_results=results, repo_root=tmp_path, rules=[], call_llm_fn=model, group_workers=1,
        verdict_updates_writer=lambda p, u: writes.append((p, u)),
    )
    for i in range(2):
        f = _finding(results, i)
        assert f["verdict"] == "unverified" and f["unresolved_reason"] == "explanation_contradiction"
        assert "asserts exploitation" in f["verdict_reason"]
    assert out["members_reviewed"] == 0 and out["error_group_count"] == 1
    update = writes[0][1][0]
    assert update["verdict"] == "unverified" and update["unresolved_reason"] == "explanation_contradiction"
    assert update["decision_detail"]["contradictions"]


# --- cost bounds: identical code once, bounded calls, short answers ------------------

def _write(tmp_path, i, header):
    path = tmp_path / "src" / f"f{i:03d}.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{header}\nimport os\npassword = 'x'\n", encoding="utf-8")


def test_identical_code_is_shown_once_and_decided_for_every_copy(tmp_path):
    # f000..f003 are the same code; f004 differs.
    for i in range(5):
        _write(tmp_path, i, "# generated" if i < 4 else "# hand written")
    results = _results(5)
    model = Model(verdicts={"src/f004.py": "false_positive"})
    _confirm(tmp_path, results, model)
    (prompt,) = model.calls
    assert "m1 | src/f000.py:3" in prompt and "stands for 3 more identical occurrence(s)" in prompt
    assert "m5 | src/f004.py:3" in prompt
    assert not re.search(r"^m[234] \|", prompt, flags=re.M)  # the copies are not shown again
    assert [_finding(results, i)["verdict"] for i in range(5)] == [
        "true_positive"] * 4 + ["false_positive"]
    assert _finding(results, 2)["review_coverage"] == {"reviewed": 5, "total": 5}


def test_a_copy_never_takes_the_verdict_of_different_code(tmp_path):
    for i in range(3):
        _write(tmp_path, i, f"# file {i}")
    results = _results(3)
    model = Model(verdicts={"src/f001.py": "false_positive"})
    _confirm(tmp_path, results, model)
    assert [_finding(results, i)["verdict"] for i in range(3)] == [
        "true_positive", "false_positive", "true_positive",
    ]


def test_one_call_shows_at_most_the_per_group_cap(tmp_path):
    n = lfs.GROUP_CONFIRM_MAX_SHOWN + 5
    for i in range(n):
        _write(tmp_path, i, f"# file {i}")
    results = _results(n)
    model = Model()
    _confirm(tmp_path, results, model)
    first, follow_up = model.calls
    assert len(re.findall(r"^m\d+ \|", first, flags=re.M)) == lfs.GROUP_CONFIRM_MAX_SHOWN
    assert len(re.findall(r"^m\d+ \|", follow_up, flags=re.M)) == 5
    assert all(_finding(results, i)["verdict"] == "true_positive" for i in range(n))


def test_batches_are_packed_by_occurrences_shown_not_by_group_count(tmp_path):
    # Three groups of 12 distinct occurrences each: two would be 24 shown, the
    # most one call may carry, so three groups need two calls even though five
    # groups per call are allowed.
    results = []
    for g in range(3):
        for i in range(12):
            n = g * 12 + i
            _write(tmp_path, n, f"# file {n}")
            finding = _member(n)
            finding["matched_text"] = f"password = '{g}'"
            results.append({"file_path": f"src/f{n:03d}.py", "findings": [finding]})
    model = BatchModel()
    lfs.group_confirm_unverified_findings(
        file_results=results, repo_root=tmp_path, rules=[], call_llm_fn=model,
        group_workers=1, usage={}, groups_per_call=5,
    )
    assert len(model.calls) == 2
    assert all(r["findings"][0]["verdict"] == "true_positive" for r in results)


class BatchModel:
    """Answers every occurrence of every pattern in a batched prompt."""

    def __init__(self):
        self.calls = []

    def __call__(self, system, user, **kwargs):
        self.calls.append(user)
        decisions = []
        parts = re.split(r"^Pattern (\d+) — occurrences", user, flags=re.M)
        for gi, body in zip(parts[1::2], parts[2::2]):
            for member in re.findall(r"^(m\d+) \|", body, flags=re.M):
                decisions.append({"group_index": int(gi), "member": member, "verdict": "true_positive",
                                  "confidence": 0.8, "verdict_reason": "ok"})
        return json.dumps({"decisions": decisions})


def test_one_fix_is_written_per_pattern_and_given_to_every_confirmed_occurrence(tmp_path):
    for i in range(3):
        _write(tmp_path, i, f"# file {i}")
    results = _results(3)

    def model(system, user, **kwargs):
        members = re.findall(r"^(m\d+) \|", user, flags=re.M)
        decisions = [{"member": m, "verdict": "true_positive", "confidence": 0.9, "verdict_reason": "real"}
                     for m in members]
        decisions[0]["ai_fix"] = "Load the password from the environment."
        return json.dumps({"decisions": decisions})

    _confirm(tmp_path, results, model)
    assert {_finding(results, i)["ai_fix"] for i in range(3)} == {"Load the password from the environment."}


def test_answers_are_asked_to_be_short():
    assert "one short sentence" in lfs._GROUP_RESPONSE_SCHEMA
    assert "FIRST true_positive occurrence" in lfs._GROUP_BATCH_RESPONSE_SCHEMA


def test_bedrock_allows_long_answers_and_does_not_retry_behind_the_app():
    import llm_client

    config = llm_client._bedrock.meta.config
    assert config.read_timeout == llm_client.BEDROCK_READ_TIMEOUT_SECONDS >= 300
    assert config.retries["total_max_attempts"] == 1
