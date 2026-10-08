"""Browser-side input probing: marker rules, a scripted driver, and the policy that gates POSTs.

The live Chromium case is marked `live` and skips when Playwright or a browser is not installed.
"""

from __future__ import annotations

import socket
from types import SimpleNamespace
from urllib.parse import quote, urlencode

import pytest

from app.dast.browser_probe import ProbeField, reflected_hits, run_probes, synthetic_checks
from app.dast.domain.active import is_loop_check
from app.dast.domain.browser_probe import (
    CHECK_DOM,
    CHECK_REFLECTED,
    CHECK_STORED,
    MarkerFactory,
    is_destructive_destination,
    is_marker_body,
    new_token,
    probe_urls,
    render,
    signals_for,
    strongest,
    verdict_for,
)
from app.dast.domain.browser_probe import BrowserObservation
from app.dast.domain.entities import Check, CheckMode, FindingVerdict, Location, Severity
from app.dast.domain.policy import MethodPolicy, RequestDescription, Scope, evaluate_request
from app.services.dast_narration import _template
from app.services.safety_guard import SafetyGuard
from tests.dast_fixtures.browser import ScriptedProbeDriver

pytestmark = pytest.mark.unit

PAGE = "http://target.test/search?q=1"
SPA = "http://target.test/spa"


class _Window:
    def __init__(self) -> None:
        self.tokens: list[str] = []

    def __call__(self, token: str):
        self.tokens.append(token)
        return self

    def __enter__(self):
        return None

    def __exit__(self, *args):
        return False


def _stored_check():
    check = Check(
        check_id=CHECK_STORED, title="Cross-site scripting (stored)",
        standards={"wstg": ("WSTG-INPV-02",), "cwe": ("CWE-79",)},
        location=Location.BODY, detector_signals=("marker_executed_in_browser", "marker_persisted_unescaped"),
        base_severity=Severity.HIGH, mode=CheckMode.OPT_IN, remediation_ref="rem-xss-stored",
    )
    return SimpleNamespace(check=check, severity=Severity.HIGH)


def _run(driver, pages, *, reflected=(), allow_stored=False, checks=None, gate=None):
    window = _Window()
    report = run_probes(
        pages=pages, reflected=reflected, driver=driver, factory=MarkerFactory("dmabcd12"),
        checks=checks or synthetic_checks(), marker_window=window, allow_stored=allow_stored,
        gate=gate, max_pages=4, max_inputs=4, pause=lambda: None, log=lambda *_: None,
    )
    return report, window


def test_marker_ids_are_unique_and_a_post_may_carry_only_that_marker():
    factory = MarkerFactory(new_token())
    first, second = factory.next_id(), factory.next_id()
    assert first != second and first.startswith(factory.token)
    payload = render("html", first)
    body = urlencode([("comment", payload), ("csrf", "abc")])
    assert is_marker_body(body, factory.token)
    assert is_marker_body({"comment": payload, "csrf": "abc"}, factory.token)
    assert not is_marker_body(urlencode([("comment", payload), ("x", "<script>")]), factory.token)
    assert not is_marker_body("comment=" + quote("DROP TABLE users"), factory.token)
    assert not is_marker_body("--boundary\r\nContent-Disposition: form-data\r\n\r\n" + payload, factory.token)
    assert is_destructive_destination("http://target.test/logout") and is_destructive_destination("/checkout")
    assert not is_destructive_destination("http://target.test/search")


def test_execution_is_the_only_confirming_signal_and_the_strongest_observation_wins():
    base = dict(mode="dom", url=PAGE, param="q", input_kind="query", marker_id="dmabcd121", payload=render("html", "dmabcd121"))
    executed = BrowserObservation(executed=True, sinks=("innerHTML",), **base)
    sunk = BrowserObservation(sinks=("innerHTML",), **base)
    quiet = BrowserObservation(**base)
    assert verdict_for(signals_for(executed)) is FindingVerdict.TRUE_POSITIVE
    assert verdict_for(signals_for(sunk)) is FindingVerdict.UNVERIFIED
    assert verdict_for(signals_for(quiet)) is None
    assert [s.name for s in signals_for(executed)] == ["marker_executed_in_browser"]
    kept = strongest([sunk, executed, quiet])
    assert len(kept) == 1 and kept[0].executed


def test_a_page_with_no_parameters_gets_one_fragment_probe():
    urls = probe_urls("http://target.test/spa", lambda name: f"marker-{name}")
    assert len(urls) == 1 and urls[0].kind == "fragment" and "marker-" in urls[0].url


def test_dom_execution_on_a_query_parameter_is_a_confirmed_finding():
    driver = ScriptedProbeDriver(execute_when=lambda url, payload: "<img" in payload and "q=" in url)
    report, window = _run(driver, [{"url": PAGE}])
    assert window.tokens == []
    assert report.summary["executed"] >= 1
    rows = [row for row in report.rows if row["rule_id"] == CHECK_DOM]
    assert rows and rows[0]["verdict"] == "true_positive"
    assert any(s["name"] == "marker_executed_in_browser" for s in rows[0]["evidence"]["signals"])


def test_a_formless_search_box_is_typed_into():
    field = ProbeField(selector="#search", name="search", kind="search", in_form=False, method="GET")
    driver = ScriptedProbeDriver(
        {"/spa": [field]},
        execute_when=lambda url, payload: url.startswith("submit:") and "<img" in payload,
    )
    report, _ = _run(driver, [{"url": SPA}])
    assert driver.submitted and driver.submitted[0][0].name == "search"
    assert any(row["rule_id"] == CHECK_DOM and row["param"] == "search" and row["verdict"] == "true_positive" for row in report.rows)


def test_a_sink_without_execution_stays_unverified_and_a_clean_page_files_nothing():
    field = ProbeField(selector="#q", name="note", kind="text")
    sunk = ScriptedProbeDriver(
        {"/clean": [field]},
        sinks_when=lambda url, payload: ("innerHTML",) if url.startswith("submit:") else (),
    )
    report, _ = _run(sunk, [{"url": "http://target.test/clean"}])
    assert report.rows and all(row["verdict"] == "unverified" for row in report.rows)
    clean = ScriptedProbeDriver({"clean": [field]})
    quiet, _ = _run(clean, [{"url": "http://target.test/clean"}])
    assert quiet.rows == [] and quiet.summary["findings"] == 0


def test_stored_marker_is_posted_only_inside_the_window_and_a_logout_form_is_skipped():
    comment = ProbeField(selector="textarea", name="comment", kind="textarea", in_form=True, method="POST", action="/comments", form_selector="form")
    logout = ProbeField(selector="#x", name="x", kind="text", in_form=True, method="POST", action="http://target.test/logout", form_selector="form")
    driver = ScriptedProbeDriver(
        {"/comments": [comment, logout]},
        live_when=lambda payload: "<img" in payload,
    )
    checks = {**synthetic_checks(), CHECK_STORED: _stored_check()}
    report, window = _run(driver, [{"url": "http://target.test/comments"}], allow_stored=True, checks=checks)
    assert window.tokens == ["dmabcd12"]
    assert [item[0].name for item in driver.submitted] == ["comment"]
    stored = [row for row in report.rows if row["rule_id"] == CHECK_STORED]
    assert stored and stored[0]["verdict"] == "unverified"
    assert any(s["name"] == "marker_persisted_unescaped" for s in stored[0]["evidence"]["signals"])


def test_reflected_http_hit_is_confirmed_only_when_the_marker_runs():
    driver = ScriptedProbeDriver(execute_when=lambda url, payload: "<img" in payload and "name=" in url)
    reflected = [{"url": "http://target.test/xss?name=old", "param": "name", "location": "query", "target": "GET http://target.test/xss"}]
    report, _ = _run(driver, [], reflected=reflected)
    rows = [row for row in report.rows if row["rule_id"] == CHECK_REFLECTED]
    assert rows and rows[0]["verdict"] == "true_positive" and rows[0]["target"] == "GET http://target.test/xss"
    silent, _ = _run(ScriptedProbeDriver(), [], reflected=reflected)
    assert silent.rows == []


def test_a_rejecting_gate_types_nothing():
    gate = SimpleNamespace(check_marker=lambda value: SimpleNamespace(ok=False))
    field = ProbeField(selector="#q", name="q", kind="text")
    driver = ScriptedProbeDriver({"/search": [field]}, execute_when=lambda url, payload: True)
    report, _ = _run(driver, [{"url": PAGE}], gate=gate)
    assert driver.submitted == [] and report.rows == []


def test_browser_only_signals_are_not_http_loop_checks_and_narration_names_the_step():
    check = Check(
        check_id=CHECK_DOM, title="DOM", standards={"cwe": ("CWE-79",)}, location=Location.QUERY,
        detector_signals=("marker_executed_in_browser", "marker_reaches_dom_sink"),
        base_severity=Severity.MEDIUM, mode=CheckMode.AUTOMATED,
    )
    assert not is_loop_check(check, check.mode)
    text = _template("browser", {"browser_probe": {"probes": 3, "executed": 1, "findings": 1}}, {}, "success")
    assert text
    skipped = _template("browser", {"browser_probe": {"skipped": "disabled"}}, {}, "success")
    assert skipped


def test_reflected_hits_come_only_from_failed_xss_checks():
    analysis = [{
        "label": "GET http://target.test/search",
        "url": "http://target.test/search",
        "checks": [
            {"check_id": "dast-xss", "verdict": "FAIL", "target": "q", "location": "query", "request": {"url": "http://target.test/search?q=1"}},
            {"check_id": "dast-xss", "verdict": "PASS", "target": "safe", "location": "query"},
            {"check_id": "dast-sqli", "verdict": "FAIL", "target": "id", "location": "query"},
        ],
    }]
    hits = reflected_hits(analysis)
    assert len(hits) == 1 and hits[0]["param"] == "q" and hits[0]["target"].startswith("GET ")


def _scope() -> Scope:
    return Scope.for_target("http://target.test/", "exact", lambda host: host)


def test_marker_post_is_allowed_only_when_every_condition_holds():
    policy = MethodPolicy(safe_mode=True, allow_marker_posts=True)
    token = "dmabcd12"
    payload = render("html", MarkerFactory(token).next_id())
    body = urlencode([("comment", payload), ("csrf", "tok")])
    allowed = evaluate_request(
        RequestDescription("POST", "http://target.test/comments", "marker_submit", body, token), _scope(), policy,
    )
    assert allowed.allowed
    denied_policy = MethodPolicy(safe_mode=True, allow_marker_posts=False)
    assert not evaluate_request(RequestDescription("POST", "http://target.test/comments", "marker_submit", body, token), _scope(), denied_policy).allowed
    assert not evaluate_request(RequestDescription("POST", "http://target.test/logout", "marker_submit", body, token), _scope(), policy).allowed
    assert not evaluate_request(RequestDescription("POST", "http://target.test/comments", "marker_submit", "comment=DROP+TABLE+users", token), _scope(), policy).allowed
    assert not evaluate_request(RequestDescription("POST", "http://evil.test/comments", "marker_submit", body, token), _scope(), policy).allowed


def test_the_guard_allows_a_marker_post_only_inside_its_window_and_under_the_cap():
    guard = SafetyGuard.from_settings(
        "http://target.test",
        {"rate_limit_per_sec": 1000, "same_domain_mode": "exact", "safe_mode": True, "browser_marker_posts": True, "opt_in_request_ceiling": 1},
        target_disposable=True,
    )
    token = "dmabcd12"
    body = urlencode([("comment", render("html", MarkerFactory(token).next_id()))])
    assert not guard.decide("POST", "http://target.test/comments", body=body).allowed
    with guard.marker_window(token):
        assert guard.decide("POST", "http://target.test/comments", body=body).allowed
        assert not guard.decide("POST", "http://target.test/comments", body=body).allowed  # cap of 1
    assert not guard.decide("POST", "http://target.test/comments", body=body).allowed
    closed = SafetyGuard.from_settings(
        "http://target.test",
        {"rate_limit_per_sec": 1000, "same_domain_mode": "exact", "safe_mode": True, "browser_marker_posts": True},
        target_disposable=False,
    )
    with closed.marker_window(token):
        assert not closed.decide("POST", "http://target.test/comments", body=body).allowed


@pytest.mark.live
def test_dom_sink_executes_the_marker_in_chromium(tmp_path):
    pytest.importorskip("playwright.sync_api")
    from playwright.sync_api import sync_playwright

    from tests.dast_fixtures.target import DOM_SINK_PAGE

    page_file = tmp_path / "dom.html"
    page_file.write_text(DOM_SINK_PAGE, encoding="utf-8")
    factory = MarkerFactory("dmabcd12")
    payload = render("html", factory.next_id())
    url = page_file.as_uri() + "?q=" + quote(payload, safe="")
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            from app.dast.browser_probe import PlaywrightProbeDriver

            driver = PlaywrightProbeDriver(page)
            driver.install(factory.token)
            hit = driver.open(url, [factory.token, payload])
            browser.close()
    except Exception as exc:  # noqa: BLE001 - no browser installed is a skip, not a failure
        pytest.skip(f"Chromium is not available: {exc}")
    assert hit.executed


def _port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), 0.3):
            return True
    except OSError:
        return False


@pytest.mark.live
def test_practice_targets_are_optional():
    juice, dvwa = _port_open(3000), _port_open(4280)
    if not juice and not dvwa:
        pytest.skip("Juice Shop (:3000) and DVWA (:4280) are not running; ground truth stays unverified")
    pytest.skip("A practice target is up. Ground truth stays verified:false until a reviewed scan is recorded.")
