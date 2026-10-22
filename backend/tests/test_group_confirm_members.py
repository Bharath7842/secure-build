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
