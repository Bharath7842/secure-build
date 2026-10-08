"""The measurement harness and the regression gate (DAST-16-010, -020, -040): scoring math, the
ground-truth format, result schema, the runner's plumbing against the mock backend, and the gate's
verdicts. Offline: the live `run` against practice targets is not part of the default suite."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from app import db as app_db
from app.config import settings
from app.main import app
from app.services.dast_catalog import default_catalog
from tools.dast_harness import gate as G
from tools.dast_harness import ground_truth as GT
from tools.dast_harness import runner, scoring
from tools.dast_harness.__main__ import main as harness_main

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[2]
HARNESS = Path(__file__).resolve().parents[1] / "tools" / "dast_harness"
KNOWN = {c.check_id for c in default_catalog().checks}


def truth(*expected, verified=True, excluded=()):
    return GT.parse(
        {
            "schema_version": 1, "target": "demo", "image": "demo@sha256:1", "verified": verified, "rule_packs": ["owasp-web-top10"],
            "expected": [{"source": "manual-verification", **e} for e in expected], "excluded": list(excluded),
        }
    )


def ref(check, target, param=None, verdict="true_positive"):
    return scoring.FindingRef(check, target, param, verdict)


SQLI = {"check_id": "dast-sqli", "endpoint": "GET /products/{id}", "param": "q"}
XSS = {"check_id": "dast-xss", "endpoint": "GET /search", "param": "term"}
BOLA = {"check_id": "dast-bola", "endpoint": "GET /orders/{id}", "param": "id", "needs": ["second_identity"]}


# ---- scoring ------------------------------------------------------------------------------------------------


def test_scoring_math_on_known_inputs():
    t = truth(SQLI, XSS, BOLA)
    findings = [ref("dast-sqli", "GET /products/17", "q"), ref("dast-cmdi", "GET /ping", "host"), ref("dast-xss", "GET /search", "term", "unverified")]
    s = scoring.score(findings, t, available=("second_identity",))
    assert (len(s.true_positives), len(s.false_positives), len(s.false_negatives)) == (1, 1, 2)  # xss unverified is not a hit; bola was expected and missed
    assert s.precision == pytest.approx(0.5) and s.recall == pytest.approx(1 / 3)
    assert s.false_negatives == ["dast-bola GET /orders/{id} [id]", "dast-xss GET /search [term]"] and s.false_positives == ["dast-cmdi GET /ping [host]"]


def test_unverified_findings_are_scored_separately_and_never_as_true_positives():
    t = truth(XSS)
    s = scoring.score([ref("dast-xss", "GET /search", "term", "unverified"), ref("dast-sqli", "GET /x", "a", "unverified")], t)
    assert s.true_positives == [] and s.false_negatives == ["dast-xss GET /search [term]"] and s.recall == 0.0
    assert s.unverified_matching == ["dast-xss GET /search [term]"] and s.unverified_other == ["dast-sqli GET /x [a]"] and s.false_positives == []
    result = scoring.build_result(s, t)
    assert result["counts"]["true_positives"] == 0 and result["counts"]["unverified"] == 2 and result["unverified"]["matching_expected"]


def test_empty_sets_use_the_documented_conventions():
    s = scoring.score([], truth())
    assert (s.precision, s.recall) == (1.0, 1.0)  # nothing claimed, nothing expected
    s = scoring.score([], truth(XSS))
    assert (s.precision, s.recall) == (1.0, 0.0)  # nothing claimed wrongly, but everything missed
    s = scoring.score([ref("dast-xss", "GET /a", "b")], truth())
    assert (s.precision, s.recall) == (0.0, 1.0)


def test_matching_uses_the_diff_key_so_ids_in_paths_and_repeats_do_not_matter():
    t = truth(SQLI)
    s = scoring.score([ref("dast-sqli", "GET /products/1", "q"), ref("dast-sqli", "GET /products/2", "q"), ref("dast-sqli", "GET /products/{id}", "q", "false_positive")], t)
    assert len(s.true_positives) == 1 and s.false_positives == [] and s.recall == 1.0


def test_expectations_the_scan_could_not_attempt_are_set_aside_not_counted_as_misses():
    t = truth(SQLI, BOLA)
    s = scoring.score([ref("dast-sqli", "GET /products/1", "q")], t, available=())
    assert s.recall == 1.0 and s.skipped_expectations == ["dast-bola GET /orders/{id} [id]"] and s.false_negatives == []


def test_the_result_file_has_a_stable_schema_and_a_readable_summary():
    t = truth(SQLI)
    s = scoring.score([ref("dast-sqli", "GET /products/1", "q")], t)
    result = scoring.build_result(s, t, scan_id="abc", duration_s=12.34, cost_usd=0.01234567, override_rate=0.25, pack_ids=["p"])
    assert set(result) == {
        "schema_version", "target", "image", "ground_truth_verified", "scan_id", "true_positives", "false_positives", "false_negatives", "unverified",
        "skipped_expectations", "counts", "precision", "recall", "guardrail_override_rate", "duration_s", "model_cost_usd", "rule_packs", "notes",
    }
    assert json.loads(json.dumps(result)) == result and result["duration_s"] == 12.3 and result["model_cost_usd"] == 0.012346
    text = scoring.summary_text(result)
    assert "precision 100.00%" in text and "recall 100.00%" in text and "$0.0123" in text and "NOT verified" not in text
    assert "NOT verified" in scoring.summary_text({**result, "ground_truth_verified": False})


def test_guardrail_override_rate_counts_downgrades_and_overrides():
    discovery = {"api_analysis": [{"checks": [{"guardrail": {"downgraded": True}}, {"guardrail": {"overridden": True}}, {"guardrail": {}}, {}]}]}
    assert scoring.guardrail_override_rate(discovery) == 0.5 and scoring.guardrail_override_rate({}) == 0.0


# ---- the ground-truth files ---------------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["dvwa", "juice-shop"])
def test_the_shipped_ground_truth_validates_names_real_checks_and_the_pinned_image(name):
    data = json.loads((HARNESS / "ground_truth" / f"{name}.json").read_text())
    compose = yaml.safe_load((ROOT / "dev" / "practice-targets" / "docker-compose.yml").read_text())
    pinned = {s["image"] for s in compose["services"].values()}
    report = GT.validate_document(data, known_check_ids=KNOWN, pinned_images=pinned)
    assert report.ok, report.errors
    assert data["verified"] is False  # honest: nobody has checked these against the pinned image yet
    assert all(e["source"] in GT.SOURCES for e in data["expected"]) and data["excluded"]
    assert "unverified" in " ".join(report.warnings)


def test_an_unverified_file_cannot_become_a_baseline():
    t = HARNESS / "ground_truth" / "dvwa.json"
    loaded = GT.load(t)
    result = scoring.build_result(scoring.score([], loaded), loaded)
    assert result["ground_truth_verified"] is False
    with pytest.raises(ValueError, match="unverified"):
        G.record_baseline(result, "/nonexistent", reason="because", update=True)


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda d: d.update(schema_version=2), "schema_version"),
        (lambda d: d.pop("image"), "image is required"),
        (lambda d: d.update(verified="yes"), "verified must be"),
        (lambda d: d["expected"][0].update(source="hearsay"), "source must name"),
        (lambda d: d["expected"][0].update(check_id="dast-made-up"), "not a catalog check"),
        (lambda d: d["expected"][0].update(endpoint="/no-method"), "look like"),
        (lambda d: d["expected"][0].update(needs=["magic"]), "unknown item"),
        (lambda d: d["expected"].append(dict(d["expected"][0])), "duplicates"),
        (lambda d: d.update(excluded=[{"description": "x"}]), "needs a description and a reason"),
        (lambda d: d.update(image="other@sha256:2"), "not one of the pinned"),
    ],
)
def test_invalid_ground_truth_is_reported(mutate, message):
    data = json.loads((HARNESS / "ground_truth" / "dvwa.json").read_text())
    mutate(data)
    compose = yaml.safe_load((ROOT / "dev" / "practice-targets" / "docker-compose.yml").read_text())
    report = GT.validate_document(data, known_check_ids=KNOWN, pinned_images={s["image"] for s in compose["services"].values()})
    assert any(message in e for e in report.errors), report.errors


def test_the_cli_validates_and_scores_files(tmp_path, capsys):
    assert harness_main(["validate"]) == 0
    findings = tmp_path / "f.json"
    findings.write_text(json.dumps({"findings": [{"rule_id": "dast-sqli", "target": "GET /vulnerabilities/sqli/", "param": "id", "verdict": "true_positive"}]}))
    assert harness_main(["score", "--findings", str(findings), "--truth", "dvwa"]) == 0
    assert "true positives" in capsys.readouterr().out


# ---- the runner (against the in-process mock backend) -------------------------------------------------------------


@pytest.fixture()
def backend(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    monkeypatch.setattr(settings, "use_mock_engine", True)
    monkeypatch.setattr(settings, "scan_logs_dir", str(tmp_path / "logs"))
    app_db.init_db(f"sqlite:///{(tmp_path / 'h.db').as_posix()}")
    return TestClient(app, headers={"Authorization": f"Bearer {settings.sast_api_token}"})


def test_the_runner_starts_a_scan_waits_scores_and_writes_a_result_and_summary(backend, tmp_path):
    result = runner.run("dvwa", backend="", token="", client=backend, sleep=lambda s: None, log=lambda *_: None)
    assert result["target"] == "dvwa" and result["scan_id"] and result["ground_truth_verified"] is False
    # SQL injection, reflected XSS and DOM XSS are misses. Stored XSS is in scope because the
    # harness turns marker posts on for that expectation. Command injection still needs state-changing methods.
    assert result["counts"]["true_positives"] == 0 and result["counts"]["false_negatives"] == 4
    assert result["skipped_expectations"] == ["dast-cmdi POST /vulnerabilities/exec/ [ip]"]
    assert result["unverified"]["other"] == []
    stamped, summary = runner.write_result(result, tmp_path)
    assert json.loads(stamped.read_text()) == result and json.loads((tmp_path / "dvwa-latest.json").read_text()) == result
    assert "precision" in summary.read_text()


def test_the_runner_reports_a_failed_scan_and_unknown_targets(backend, monkeypatch):
    with pytest.raises(runner.HarnessError, match="unknown target"):
        runner.run("nope", backend="", token="", client=backend)
    monkeypatch.setattr(settings, "use_mock_engine", False)
    monkeypatch.setattr(settings, "run_dast", False)
    monkeypatch.setenv("USE_MOCK_ENGINE", "false")
    with pytest.raises(runner.HarnessError, match="ended failed"):
        runner.run("dvwa", backend="", token="", client=backend, sleep=lambda s: __import__("time").sleep(0.05), poll_s=0.05, log=lambda *_: None)


def test_scan_payload_and_identity_parsing():
    target = runner.load_targets()["juice-shop"]
    t = GT.load(HARNESS / target["truth"])
    payload = runner.scan_payload("p1", target, t, [runner.parse_identity("alice:User:alice@x.test:pw:with:colons")])
    ident = payload["dast"]["identities"][0]
    assert ident["password"] == "pw:with:colons" and ident["login_url"] == target["login_url"] and payload["dast"]["rule_packs"] == list(t.rule_packs)
    with pytest.raises(runner.HarnessError):
        runner.parse_identity("only:two")


# ---- the regression gate ------------------------------------------------------------------------------------------


def result(target="dvwa", recall=0.8, precision=0.7, verified=True, image="img@sha256:1"):
    return {"target": target, "recall": recall, "precision": precision, "ground_truth_verified": verified, "image": image}


BASE = {"target": "dvwa", "recall": 0.8, "precision": 0.7, "image": "img@sha256:1"}


def test_a_lower_recall_fails_the_gate_and_an_equal_or_better_result_passes():
    assert not G.evaluate({"dvwa": result(recall=0.79)}, {"dvwa": BASE}).passed
    assert G.evaluate({"dvwa": result()}, {"dvwa": BASE}).passed
    better = G.evaluate({"dvwa": result(recall=0.9, precision=0.8)}, {"dvwa": BASE})
    assert better.passed and better.rows[0].recall_delta == 0.1


def test_precision_may_drift_within_the_tolerance_and_no_further():
    assert G.evaluate({"dvwa": result(precision=0.7 - G.PRECISION_TOLERANCE + 0.001)}, {"dvwa": BASE}).passed
    failing = G.evaluate({"dvwa": result(precision=0.7 - G.PRECISION_TOLERANCE - 0.01)}, {"dvwa": BASE})
    assert not failing.passed and "precision dropped" in failing.failures[0]


def test_an_unverified_or_differently_pinned_result_is_not_comparable():
    assert not G.evaluate({"dvwa": result(verified=False)}, {"dvwa": BASE}).passed
    other = G.evaluate({"dvwa": result(image="img@sha256:2")}, {"dvwa": BASE})
    assert not other.passed and "different image" in other.failures[0]


def test_no_baseline_is_a_note_unless_one_is_required():
    report = G.evaluate({"dvwa": result()}, {})
    assert report.passed and report.rows[0].status == "no-baseline"
    assert not G.evaluate({"dvwa": result()}, {}, require_baseline=True).passed


def test_a_red_suite_or_layering_test_fails_the_gate_with_the_reason_named():
    assert not G.evaluate({}, {}, suite_ok=False).passed
    report = G.evaluate({}, {}, suite_ok=True, layering_ok=False)
    assert not report.passed and report.failures == ["the layering test is red"]
    assert G.evaluate({}, {}, suite_ok=True, layering_ok=True).passed


def test_the_pipeline_summary_shows_per_target_deltas():
    text = G.render_markdown(G.evaluate({"dvwa": result(recall=0.9), "juice-shop": result("juice-shop")}, {"dvwa": BASE}))
    assert "PASS" in text and "| dvwa | pass | 90.0% | +10.0% |" in text and "juice-shop" in text and "no baseline" in text
    assert "FAIL" in G.render_markdown(G.evaluate({"dvwa": result(recall=0.1)}, {"dvwa": BASE}))


def test_baselines_change_only_with_the_explicit_flag_a_reason_and_verified_truth(tmp_path):
    good = {**result(), "counts": {}, "scan_id": "s1"}
    with pytest.raises(PermissionError):
        G.record_baseline(good, tmp_path, reason="r", update=False)
    with pytest.raises(ValueError, match="reason"):
        G.record_baseline(good, tmp_path, reason="  ", update=True)
    path = G.record_baseline(good, tmp_path, reason="first verified run", update=True)
    saved = json.loads(path.read_text())
    assert saved["recall"] == 0.8 and saved["reason"] == "first verified run" and saved["from_scan"] == "s1"
    assert G.evaluate({"dvwa": result(recall=0.5)}, G.load_json_dir(tmp_path)).passed is False


def test_the_cli_gate_exits_nonzero_on_a_regression(tmp_path, capsys):
    results, baselines = tmp_path / "r", tmp_path / "b"
    results.mkdir(), baselines.mkdir()
    (baselines / "dvwa.json").write_text(json.dumps(BASE))
    (results / "dvwa-latest.json").write_text(json.dumps(result(recall=0.5)))
    assert harness_main(["gate", "--results", str(results), "--baselines", str(baselines)]) == 1
    assert "FAIL" in capsys.readouterr().out
    (results / "dvwa-latest.json").write_text(json.dumps(result()))
    assert harness_main(["gate", "--results", str(results), "--baselines", str(baselines)]) == 0
    with pytest.raises(ValueError, match="reason"):
        harness_main(["gate", "--update-baseline", "--result", str(results / "dvwa-latest.json"), "--baselines", str(baselines), "--reason", ""])
    assert harness_main(["gate", "--update-baseline", "--result", str(results / "dvwa-latest.json"), "--baselines", str(baselines), "--reason", "new reference"]) == 0
    assert json.loads((baselines / "dvwa.json").read_text())["reason"] == "new reference"
