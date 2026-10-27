"""DAST-03-010 / -020 / -030: check schema, catalog loader and the default packs."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from app.dast.domain import catalog as C
from app.dast.domain.detectors import signal_names
from app.dast.domain.entities import CheckMode, Location, Severity
from app.services import dast_catalog as L

pytestmark = pytest.mark.unit

SIGNALS = signal_names()


def valid(**over):
    base = {
        "id": "dast-demo", "title": "Demo", "owasp": ["A03:2021"], "cwe": ["CWE-89"], "location": "query",
        "signal": ["db_error_surfaced"], "severity": "HIGH", "mode": "automated", "remediation_ref": "rem-sqli",
    }
    base.update(over)
    return base


def parse(items, exists=lambda ref: True):
    return C.parse_checks(items, signal_names=SIGNALS, remediation_exists=exists)


def messages(result):
    return [i.message for i in result.errors]


# ---- schema -----------------------------------------------------------------------------------


def test_a_valid_check_loads():
    result = parse([valid()])
    (check,) = result.checks
    assert result.issues == ()
    assert check.location is Location.QUERY and check.base_severity is Severity.HIGH and check.mode is CheckMode.AUTOMATED
    assert check.standards["owasp"] == ("A03:2021",) and check.detector_signals == ("db_error_surfaced",)


@pytest.mark.parametrize(
    "mutation, expected",
    [
        ({"severity": "SEVERE"}, "severity"),
        ({"location": "cookie"}, "location"),
        ({"mode": "sometimes"}, "mode"),
        ({"id": "no-prefix"}, "must start with"),
        ({"id": "dast-bad id"}, "may contain only"),
        ({"owasp": [], "cwe": []}, "standard tag"),
        ({"owasp": "A03"}, "owasp must be a list"),
        ({"surprise": 1}, "unknown field 'surprise'"),
        ({"dependencies": {"coffee": "skip"}}, "unknown dependency"),
        ({"dependencies": {"oast": "maybe"}}, "dependencies.oast"),
        ({"applies_to": {"flavour": 1}}, "applies_to has unknown key"),
        ({"applies_to": {"locations": ["moon"]}}, "not a valid location"),
        ({"signal": "db_error_surfaced"}, "signal must be a list"),
    ],
)
def test_each_failure_mode_has_a_specific_error(mutation, expected):
    result = parse([valid(**mutation)])
    assert result.checks == ()
    assert any(expected in m for m in messages(result)), messages(result)


@pytest.mark.parametrize("field", ["payload", "payloads", "body", "value", "inputs", "wordlist", "raw", "fuzz"])
def test_a_field_that_could_carry_a_payload_is_rejected(field):
    result = parse([valid(**{field: "' OR 1=1 --"})])
    assert result.checks == ()
    assert any("fixed payload" in m and repr(field) in m for m in messages(result))


def test_missing_required_fields_are_named():
    result = parse([{"id": "dast-x"}])
    named = " ".join(messages(result))
    for field in ("title", "location", "severity", "mode", "remediation_ref"):
        assert f"'{field}'" in named


def test_duplicate_ids_fail_and_name_the_first_definition():
    result = parse([valid(), valid(title="Again")])
    assert len(result.checks) == 1
    assert any("duplicate id" in m and "item 0" in m for m in messages(result))


def test_alias_cannot_collide_with_another_id():
    result = parse([valid(), valid(id="dast-other", aliases=["dast-demo"])])
    assert [c.check_id for c in result.checks] == ["dast-demo"]
    assert any("alias" in m for m in messages(result))


def test_unknown_signal_downgrades_to_assist_only_and_is_flagged():
    result = parse([valid(signal=["not_a_detector"])])
    (check,) = result.checks
    assert check.mode is CheckMode.ASSIST_ONLY and check.detector_signals == ()
    assert set(check.flags) == {"unknown_signal", "no_resolvable_signal"}
    assert result.errors == () and any("not_a_detector" in n.message for n in result.notes)


def test_known_signals_survive_alongside_unknown_ones():
    (check,) = parse([valid(signal=["db_error_surfaced", "typo_signal"])]).checks
    assert check.detector_signals == ("db_error_surfaced",) and check.mode is CheckMode.AUTOMATED
    assert check.flags == ("unknown_signal",)


def test_declared_assist_only_with_no_signal_is_allowed():
    (check,) = parse([valid(signal=[], mode="assist-only")]).checks
    assert check.mode is CheckMode.ASSIST_ONLY and "no_resolvable_signal" in check.flags


def test_remediation_must_resolve():
    result = parse([valid(remediation_ref="rem-missing")], exists=lambda ref: ref != "rem-missing")
    assert any("does not resolve" in m for m in messages(result))


def test_passive_check_may_not_name_active_signals():
    result = parse([valid(passive=True, signal=["db_error_surfaced"])])
    assert any("passive check names active signal" in m for m in messages(result))
    assert parse([valid(passive=True, signal=["header_absent"])]).checks


def test_load_generating_and_opt_in_checks_are_not_enabled_by_default():
    (a,) = parse([valid(load_generating=True)]).checks
    (b,) = parse([valid(mode="opt-in")]).checks
    (c,) = parse([valid(enabled=False)]).checks
    (d,) = parse([valid()]).checks
    assert [x.enabled_by_default for x in (a, b, c, d)] == [False, False, False, True]


def test_strict_signals_rejects_a_typo_but_accepts_none():
    kw = dict(signal_names=SIGNALS, remediation_exists=lambda r: True, strict_signals=True)
    check, issues = C.parse_check(valid(signal=["db_error_surfaced", "typo"]), 0, **kw)
    assert check is None and any("unknown detector signal" in i.message for i in issues)
    check, issues = C.parse_check(valid(signal=[]), 0, **kw)
    assert check is not None and check.mode is CheckMode.ASSIST_ONLY


def test_standards_labels_cover_every_tag():
    (check,) = parse([valid(owasp=["A03:2021"], apisec=["API8:2023"], wstg=["WSTG-INPV-05"], cwe=["CWE-89"])]).checks
    assert C.standards_for(check) == ["OWASP A03:2021", "OWASP API8:2023", "WSTG-INPV-05", "CWE-89"]


def test_check_dict_round_trip():
    (check,) = parse([valid(dependencies={"oast": "assist-only"}, degraded_note="x", aliases=["dast-old"])]).checks
    assert C.check_from_dict(C.check_to_dict(check)) == check


# ---- loader -----------------------------------------------------------------------------------


def write_dir(tmp_path: Path, checks: str, packs: str = "[]", remediation=("rem-sqli",)) -> Path:
    (tmp_path / "remediation").mkdir(parents=True, exist_ok=True)
    (tmp_path / L.CATALOG_FILE).write_text(checks)
    (tmp_path / L.PACKS_FILE).write_text(packs)
    for ref in remediation:
        (tmp_path / "remediation" / f"{ref}.md").write_text("# x\n")
    return tmp_path


def test_loader_reports_file_and_line(tmp_path):
    text = yaml.safe_dump([valid(), valid(id="dast-two", severity="BOGUS")], sort_keys=False)
    with pytest.raises(L.CatalogLoadError) as err:
        L.load_catalog(write_dir(tmp_path, text))
    (issue,) = err.value.issues
    assert issue.file == L.CATALOG_FILE and issue.line is not None and issue.line > 1
    assert "dast-two" in str(issue) and "severity" in str(issue)
    lines = text.splitlines()
    assert lines[issue.line - 1].startswith("- id: dast-two")


def test_loader_reports_all_problems_at_once(tmp_path):
    text = yaml.safe_dump([valid(severity="x"), valid(id="dast-b", mode="y")], sort_keys=False)
    with pytest.raises(L.CatalogLoadError) as err:
        L.load_catalog(write_dir(tmp_path, text))
    assert len(err.value.issues) == 2


def test_loader_rejects_bad_yaml_and_missing_remediation_file(tmp_path):
    with pytest.raises(L.CatalogLoadError, match="invalid YAML"):
        L.load_catalog(write_dir(tmp_path / "a", "- id: [unclosed"))
    with pytest.raises(L.CatalogLoadError, match="does not resolve"):
        L.load_catalog(write_dir(tmp_path / "b", yaml.safe_dump([valid()]), remediation=()))


def test_remediation_refs_cannot_escape_the_directory(tmp_path):
    assert L.remediation_path("../secrets") is None and L.remediation_path("a/b") is None
    assert L.remediation_text("../../etc/passwd") == ""
    assert not L.remediation_exists("")


def test_loader_validates_packs(tmp_path):
    packs = yaml.safe_dump([{"id": "p", "select": {"ids": ["dast-nope"]}}])
    with pytest.raises(L.CatalogLoadError, match="unknown check"):
        L.load_catalog(write_dir(tmp_path, yaml.safe_dump([valid()]), packs))


# ---- the shipped catalog and packs ------------------------------------------------------------

CATALOG = L.load_catalog()


def test_shipped_catalog_loads_clean():
    assert len(CATALOG.checks) >= 25
    assert not [c for c in CATALOG.checks if "unknown_signal" in c.flags]


def test_every_check_has_a_remediation_file_and_standards():
    for check in CATALOG.checks:
        assert L.remediation_text(check.remediation_ref).startswith("# "), check.check_id
        assert check.standards.get("cwe"), check.check_id
        assert not any(f in check.flags for f in ("unknown_signal",)), check.check_id


def test_api_pack_covers_all_ten_risks_with_the_specified_modes():
    by_risk: dict[str, list] = {}
    for check in CATALOG.pack_checks("owasp-api-top10-2023"):
        for tag in check.standards.get("apisec", ()):
            by_risk.setdefault(tag.split(":")[0], []).append(check)
    assert set(by_risk) == {f"API{n}" for n in range(1, 11)}

    def modes(risk):
        return {c.mode for c in by_risk[risk]}

    for risk in ("API1", "API5", "API8", "API9"):
        assert modes(risk) == {CheckMode.AUTOMATED}, risk
    assert modes("API2") == {CheckMode.AUTOMATED, CheckMode.OPT_IN}
    assert {c.check_id for c in by_risk["API2"] if c.mode is CheckMode.OPT_IN} == {"dast-jwt-weak-secret"}
    assert CheckMode.AUTOMATED in modes("API3") and CheckMode.AUTOMATED in modes("API7")
    assert modes("API4") == {CheckMode.OPT_IN}
    assert modes("API6") == {CheckMode.ASSIST_ONLY} and modes("API10") == {CheckMode.ASSIST_ONLY}
    for check in CATALOG.pack_checks("owasp-api-top10-2023"):
        assert check.standards.get("owasp") and check.standards.get("apisec") and check.standards.get("cwe"), check.check_id


def test_api4_is_off_by_default_and_api7_needs_oast():
    api4 = CATALOG.get("dast-resource-consumption")
    assert api4 and api4.load_generating and not api4.enabled_by_default
    ssrf = CATALOG.get("dast-ssrf")
    assert ssrf and ssrf.on_missing == {"oast": "assist-only"}
    assert CATALOG.get("dast-bola").on_missing == {"second_identity": "degrade"}


def test_legacy_ids_and_aliases_resolve():
    for legacy in ("dast-sqli", "dast-xss", "dast-misconfig"):
        assert CATALOG.get(legacy) is not None
    assert CATALOG.resolve_id("dast-authz") == "dast-bola" and CATALOG.get("dast-authz").check_id == "dast-bola"
    assert CATALOG.resolve_id("dast-unknown") == "dast-unknown" and CATALOG.get("dast-unknown") is None


def test_packs_are_selections_and_overlap_resolves_to_one_instance():
    names = {p.pack_id for p in CATALOG.packs}
    assert {"owasp-api-top10-2023", "owasp-web-top10", "wstg-full", "passive-only", "thorough"} <= names
    web = {c.check_id for c in CATALOG.pack_checks("owasp-web-top10")}
    api = {c.check_id for c in CATALOG.pack_checks("owasp-api-top10-2023")}
    assert web & api  # a check may belong to several packs
    ids_in_web = [c.check_id for c in CATALOG.pack_checks("owasp-web-top10")]
    assert len(ids_in_web) == len(set(ids_in_web))


def test_browser_xss_checks_are_split_between_the_web_pack_and_the_thorough_pack():
    dom = CATALOG.get("dast-xss-dom")
    stored = CATALOG.get("dast-xss-stored")
    reflected = CATALOG.get("dast-xss")
    assert dom is not None and stored is not None and reflected is not None
    assert dom.mode is CheckMode.AUTOMATED and "A03:2021" in dom.standards["owasp"]
    assert "marker_executed_in_browser" in reflected.detector_signals
    assert stored.mode is CheckMode.OPT_IN and not stored.enabled_by_default and not stored.standards.get("owasp")
    thorough = next(p for p in CATALOG.packs if p.pack_id == "thorough")
    assert not thorough.enabled_by_default
    assert "dast-xss-stored" in C.pack_check_ids(thorough, CATALOG.checks)
    assert "dast-xss-stored" not in {c.check_id for c in CATALOG.pack_checks("owasp-web-top10")}
    assert "dast-xss-dom" in {c.check_id for c in CATALOG.pack_checks("owasp-web-top10")}


def test_passive_only_has_no_active_check():
    checks = CATALOG.pack_checks("passive-only")
    assert checks and all(c.passive for c in checks)
    from app.dast.domain.detectors import DETECTORS

    for check in checks:
        assert not set(check.detector_signals) & set(DETECTORS), check.check_id
    assert "dast-sqli" not in {c.check_id for c in checks}


def test_tag_selection_returns_the_expected_ids():
    pack = C.PackDef("t", "t", tags={"cwe": ("CWE-89",)})
    assert C.pack_check_ids(pack, CATALOG.checks) == ["dast-sqli"]
    wstg = C.PackDef("t", "t", tags={"wstg": ("WSTG-INPV",)})
    assert {"dast-sqli", "dast-xss", "dast-cmdi", "dast-ssrf"} <= set(C.pack_check_ids(wstg, CATALOG.checks))
    by_id = C.PackDef("t", "t", ids=("dast-authz", "dast-sqli"))  # an alias is accepted
    assert C.pack_check_ids(by_id, CATALOG.checks) == ["dast-bola", "dast-sqli"]


def test_every_signal_a_check_names_exists():
    for check in CATALOG.checks:
        assert set(check.detector_signals) <= SIGNALS, check.check_id


def test_parse_check_yaml_for_a_custom_rule():
    text = yaml.safe_dump(valid(id="dast-custom-a"))
    check, errors, notes = L.parse_check_yaml(text, version=3)
    assert check and check.source == "custom" and check.version == 3 and not errors
    assert L.parse_check_yaml("- a\n- b")[1] and L.parse_check_yaml("id: [")[1]
    assert L.parse_check_yaml(yaml.safe_dump(valid(payload="x")))[0] is None
    default_ref = L.parse_check_yaml(yaml.safe_dump({k: v for k, v in valid().items() if k != "remediation_ref"}))[0]
    assert default_ref.remediation_ref == "rem-custom"
