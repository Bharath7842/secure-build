"""DAST-03-040 / -060: resolution order, overrides, snapshots and dependency evaluation (pure)."""

from __future__ import annotations

import itertools

import pytest

from app.dast.domain import ruleset as R
from app.dast.domain.entities import CheckMode, Severity
from app.services.dast_catalog import load_catalog

pytestmark = pytest.mark.unit

CATALOG = load_catalog()


def cfg(packs=None, checks=None):
    return R.parse_rule_config({"packs": packs or {}, "checks": checks or {}}, CATALOG)


def resolve(g=None, p=None, s=None):
    return R.resolve_effective_rule_set(CATALOG, g, p, s)


def ids(rs):
    return {c.check_id for c in rs.enabled_checks()}


def test_defaults_enable_the_api_and_web_packs():
    rs = resolve()
    assert rs.pack_ids == ("owasp-api-top10-2023", "owasp-web-top10")
    assert "dast-sqli" in ids(rs) and "dast-bola" in ids(rs)


def test_load_generating_check_stays_off_regardless_of_pack():
    rs = resolve()
    api4 = rs.get("dast-resource-consumption")
    assert api4 is not None and not api4.enabled
    only_api = resolve(s=cfg(packs={"owasp-web-top10": False}))
    assert not only_api.get("dast-resource-consumption").enabled
    explicit = resolve(s=cfg(checks={"dast-resource-consumption": {"enabled": True}}))
    assert explicit.get("dast-resource-consumption").enabled


@pytest.mark.parametrize("levels", list(itertools.product([None, True, False], repeat=3)))
def test_later_levels_override_earlier_for_a_pack_flag(levels):
    configs = [cfg(packs={"wstg-full": v}) if v is not None else None for v in levels]
    expected = False  # wstg-full is off by default
    for v in levels:
        if v is not None:
            expected = v
    assert ("wstg-full" in resolve(*configs).pack_ids) is expected


@pytest.mark.parametrize("levels", list(itertools.product([None, "LOW", "CRITICAL"], repeat=3)))
def test_later_levels_override_earlier_for_severity(levels):
    configs = [cfg(checks={"dast-sqli": {"severity": v}}) if v else None for v in levels]
    expected = Severity.HIGH  # catalog base
    for v in levels:
        if v:
            expected = Severity(v)
    assert resolve(*configs).get("dast-sqli").severity is expected


def test_overrides_merge_field_by_field_across_levels():
    rs = resolve(
        g=cfg(checks={"dast-sqli": {"severity": "LOW"}}),
        p=cfg(checks={"dast-sqli": {"mode": "opt-in"}}),
        s=cfg(checks={"dast-sqli": {"enabled": True}}),
    )
    sqli = rs.get("dast-sqli")
    assert sqli.severity is Severity.LOW and sqli.mode is CheckMode.OPT_IN and sqli.enabled
    assert sqli.overrides == {"enabled": True, "severity": "LOW", "mode": "opt-in"}


def test_a_check_disabled_in_a_pack_is_listed_but_not_enabled():
    rs = resolve(p=cfg(checks={"dast-xss": {"enabled": False}}))
    xss = rs.get("dast-xss")
    assert xss is not None and not xss.enabled and "dast-xss" not in ids(rs)


def test_opt_in_mode_override_needs_explicit_enable():
    assert not resolve(s=cfg(checks={"dast-xss": {"mode": "opt-in"}})).get("dast-xss").enabled
    assert resolve(s=cfg(checks={"dast-xss": {"mode": "opt-in", "enabled": True}})).get("dast-xss").enabled


def test_mode_override_cannot_give_a_check_evidence_it_lacks():
    rs = resolve(s=cfg(checks={"dast-business-flows": {"mode": "automated", "enabled": True}}))
    flows = rs.get("dast-business-flows")
    assert flows.mode is CheckMode.ASSIST_ONLY and flows.notes and "no detector signal" in flows.notes[0]


def test_unselected_checks_are_absent():
    rs = resolve(g=cfg(packs={"owasp-api-top10-2023": False, "owasp-web-top10": False, "passive-only": True}))
    assert rs.pack_ids == ("passive-only",)
    assert all(c.check.passive for c in rs.checks)
    assert rs.get("dast-sqli") is None


def test_list_form_means_exactly_these_packs():
    rs = resolve(s=R.parse_rule_config({"packs": ["passive-only"]}, CATALOG))
    assert rs.pack_ids == ("passive-only",)


@pytest.mark.parametrize(
    "raw",
    [
        {"packs": {"nope": True}}, {"packs": ["nope"]}, {"packs": {"wstg-full": "yes"}},
        {"checks": {"dast-nope": {"enabled": True}}}, {"checks": {"dast-sqli": {"severity": "SEVERE"}}},
        {"checks": {"dast-sqli": {"payload": "x"}}}, {"checks": {"dast-sqli": {"mode": "sometimes"}}},
        {"checks": {"dast-sqli": {"enabled": "yes"}}}, {"surprise": 1}, "text", {"packs": 5},
    ],
)
def test_invalid_configuration_is_rejected(raw):
    with pytest.raises(R.RuleConfigError):
        R.parse_rule_config(raw, CATALOG)


def test_aliases_are_accepted_in_overrides():
    config = R.parse_rule_config({"checks": {"dast-authz": {"severity": "CRITICAL"}}}, CATALOG)
    assert resolve(s=config).get("dast-bola").severity is Severity.CRITICAL


def test_patch_merge_semantics():
    base = cfg(packs={"wstg-full": True}, checks={"dast-sqli": {"severity": "LOW"}})
    patch = cfg(checks={"dast-sqli": {"mode": "opt-in"}, "dast-xss": {"enabled": False}})
    merged = patch.merged_over(base)
    assert merged.packs == {"wstg-full": True}
    assert merged.checks["dast-sqli"].severity is Severity.LOW and merged.checks["dast-sqli"].mode is CheckMode.OPT_IN
    assert merged.checks["dast-xss"].enabled is False


def test_snapshot_is_self_contained_and_round_trips():
    rs = resolve(s=cfg(checks={"dast-sqli": {"severity": "LOW"}}))
    snap = R.effective_to_dict(rs, "abc123")
    assert snap["catalog_version"] == "abc123" and snap["packs"] == list(rs.pack_ids)
    import json

    again = R.effective_from_dict(json.loads(json.dumps(snap)))
    assert again.pack_ids == rs.pack_ids
    assert [(c.check_id, c.enabled, c.severity, c.mode) for c in again.checks] == [
        (c.check_id, c.enabled, c.severity, c.mode) for c in rs.checks
    ]
    assert again.get("dast-sqli").check == rs.get("dast-sqli").check


# ---- dependency evaluation --------------------------------------------------------------------


def evaluate(**inputs):
    return {e["check_id"]: e for e in R.evaluate_dependencies(resolve(), R.ScanInputs(**inputs))}


def test_missing_second_identity_degrades_bola_and_bfla_with_a_reason():
    out = evaluate(has_second_identity=False, oast_configured=True)
    bola = out["dast-bola"]
    assert bola["status"] == "degraded" and bola["dependency"] == "second_identity"
    assert bola["reason"].endswith("ran no-session replay only: no second identity was supplied")
    assert "anonymous replay only" in out["dast-bfla"]["reason"]


def test_missing_oast_makes_ssrf_assist_only():
    ssrf = evaluate(has_second_identity=True, oast_configured=False)["dast-ssrf"]
    assert ssrf["status"] == "degraded" and ssrf["effective_mode"] == "assist-only"
    assert "no OAST callback address" in ssrf["reason"]


def test_all_dependencies_met_yields_nothing():
    assert evaluate(has_second_identity=True, oast_configured=True) == {}


def test_schema_dependency_only_judged_once_known():
    assert "dast-api-inventory" not in evaluate(has_second_identity=True, oast_configured=True)
    out = evaluate(has_second_identity=True, oast_configured=True, schema_present=False)
    assert out["dast-api-inventory"]["status"] == "skipped" and "no API schema" in out["dast-api-inventory"]["reason"]
    assert out["dast-mass-assignment"]["status"] == "degraded"
    assert "dast-api-inventory" not in evaluate(has_second_identity=True, oast_configured=True, schema_present=True)


def test_disabled_and_assist_only_checks_are_not_evaluated():
    rs = resolve(s=cfg(checks={"dast-bola": {"enabled": False}}))
    out = {e["check_id"] for e in R.evaluate_dependencies(rs, R.ScanInputs())}
    assert "dast-bola" not in out
    assert "dast-resource-consumption" not in out  # API4 is off, so it is not "skipped"


def test_merge_dependency_results_later_wins_without_duplicates():
    first = [{"check_id": "a", "status": "degraded"}, {"check_id": "b", "status": "skipped"}]
    second = [{"check_id": "b", "status": "degraded"}, {"check_id": "c", "status": "skipped"}]
    merged = R.merge_dependency_results(first, second)
    assert {e["check_id"]: e["status"] for e in merged} == {"a": "degraded", "b": "degraded", "c": "skipped"}
