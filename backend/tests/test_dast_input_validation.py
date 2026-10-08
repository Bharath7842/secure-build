"""DAST-01-060: non-destructive input validator (pure, table-driven)."""

from __future__ import annotations

import copy
import json
import logging
from pathlib import Path

import pytest

from app.dast.domain.validation import (
    METHOD_GATE_RULE,
    ProposedTest,
    parse_rule_list,
    validate_test_input,
)
from app.dast.input_gate import DEFAULT_RULES_PATH, InputGate, default_rule_list, load_rule_list

pytestmark = pytest.mark.unit

FIXTURE = Path(__file__).parent / "fixtures" / "input_validation_cases.json"
CASES = json.loads(FIXTURE.read_text(encoding="utf-8"))["cases"]


def _id(case: dict) -> str:
    return f"{case['expect']}:{case['value'][:30]!r}:{case['method']}"


def test_fixture_has_at_least_forty_cases_of_each_kind_mix():
    assert len(CASES) >= 40
    assert sum(c["expect"] == "reject" for c in CASES) >= 20
    assert sum(c["expect"] == "accept" for c in CASES) >= 20


@pytest.mark.parametrize("case", CASES, ids=[_id(c) for c in CASES])
def test_payload_is_classified_correctly(case):
    result = validate_test_input(
        ProposedTest(case["method"], case["location"], case["value"]),
        default_rule_list(),
        safe_mode=case.get("safe_mode", True),
        allow_state_changing=case.get("allow_state_changing", False),
    )
    assert result.ok == (case["expect"] == "accept"), (case, result)
    if case["expect"] == "reject":
        assert result.reason  # rejection reason recorded
        assert result.rule_id
        if case.get("rule"):
            assert result.rule_id == case["rule"], (case, result)
    else:
        assert result.reason == "" and result.rule_id == ""


# ---- method gate interplay ------------------------------------------------------------------


def test_state_changing_method_needs_safe_mode_off_or_opt_in():
    rules = default_rule_list()
    probe = ProposedTest("POST", "body", "dast-probe-1")
    assert validate_test_input(probe, rules).rule_id == METHOD_GATE_RULE
    assert validate_test_input(probe, rules, safe_mode=False).ok
    assert validate_test_input(probe, rules, allow_state_changing=True).ok
    # Safe methods never need the opt-in.
    assert validate_test_input(ProposedTest("GET", "query", "x"), rules).ok
    assert validate_test_input(ProposedTest("head", "query", "x"), rules).ok


def test_destructive_value_is_rejected_even_when_the_method_is_allowed():
    result = validate_test_input(
        ProposedTest("POST", "body", "'; DROP TABLE users--"), default_rule_list(), safe_mode=False
    )
    assert not result.ok and result.rule_id == "sql-ddl"


def test_non_string_value_does_not_raise():
    assert validate_test_input(ProposedTest("GET", "query", 12345), default_rule_list()).ok  # type: ignore[arg-type]


# ---- rule list is data ----------------------------------------------------------------------


def _base_data() -> dict:
    return json.loads(Path(DEFAULT_RULES_PATH).read_text(encoding="utf-8"))


def test_default_rule_file_is_versioned_and_loads():
    data = _base_data()
    assert data["schema_version"] == 1 and data["version"] >= 1
    rules = load_rule_list()
    assert len(rules.rules) == len(data["deny"])


def test_a_new_rule_takes_effect_without_code_changes():
    data = copy.deepcopy(_base_data())
    data["deny"].append({"id": "custom-ban", "reason": "site-specific verb", "pattern": r"\bpurge_all\b"})
    probe = ProposedTest("GET", "query", "purge_all")
    assert validate_test_input(probe, default_rule_list()).ok
    result = validate_test_input(probe, parse_rule_list(data))
    assert not result.ok and result.rule_id == "custom-ban"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(schema_version=99),
        lambda d: d["deny"].append({"id": "sql-ddl", "reason": "dup", "pattern": "x"}),
        lambda d: d["deny"].append({"id": "bad-re", "reason": "r", "pattern": "("}),
        lambda d: d["deny"].append({"id": "no-reason", "pattern": "x"}),
        lambda d: d["deny"].append({"id": "bad-flag", "reason": "r", "pattern": "x", "flags": "z"}),
    ],
)
def test_malformed_rule_list_fails_loudly(mutate):
    data = copy.deepcopy(_base_data())
    mutate(data)
    with pytest.raises(ValueError):
        parse_rule_list(data)


def test_a_pathological_input_is_bounded():
    # Decoding views are capped, so a deeply nested encoding cannot blow up the validator.
    value = "%25" * 600  # 1800 chars, within the length limit
    assert validate_test_input(ProposedTest("GET", "query", value), default_rule_list()).ok


# ---- gate: counting and logging, never storing ----------------------------------------------


def test_gate_counts_and_logs_rejections_without_keeping_the_value(caplog):
    lines: list[str] = []
    gate = InputGate(log=lines.append)
    secret_payload = "'; DROP TABLE customers_7731--"

    with caplog.at_level(logging.WARNING):
        assert gate.check(ProposedTest("GET", "query", "dast-probe-2")).ok
        assert not gate.check(ProposedTest("GET", "query", secret_payload)).ok
        assert not gate.check(ProposedTest("POST", "body", "x")).ok

    assert gate.accepted == 1 and gate.rejected == 2
    assert gate.rejected_by_rule == {"sql-ddl": 1, METHOD_GATE_RULE: 1}
    assert len(lines) == 2 and "rule=sql-ddl" in lines[0] and "len=" in lines[0]
    blob = "\n".join(lines) + "\n" + caplog.text + json.dumps(gate.summary())
    assert "customers_7731" not in blob and "DROP TABLE" not in blob


def test_gate_fails_closed_when_the_validator_errors(monkeypatch):
    import app.dast.input_gate as module

    def boom(*args, **kwargs):
        raise RuntimeError("bug")

    monkeypatch.setattr(module, "validate_test_input", boom)
    result = InputGate().check(ProposedTest("GET", "query", "x"))
    assert not result.ok and result.rule_id == "validator-error"


def test_gate_respects_its_safe_mode_settings():
    gate = InputGate(safe_mode=False)
    assert gate.check(ProposedTest("POST", "body", "dast-probe-3")).ok
