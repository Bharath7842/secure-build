"""Browser-side input probing: type an inert marker, then see whether the page runs it.

The orchestration (`run_probes`) talks to a `ProbeDriver`. The Playwright driver is one
implementation; tests supply a fake. Playwright is imported only inside that driver, and only
when a probe actually runs.

Three passes, capped by the scan's page and per-page input budgets:

* **DOM / reflected (GET).** Load each crawled page with a marker in each query parameter, and type
  a marker into each visible text input, including inputs that have no `<form>` (SPA search boxes).
* **Reflected confirmation.** For each `dast-xss` failure the HTTP stage already recorded, reload
  that parameter with *this scan's* marker. Execution upgrades that finding; anything less leaves
  the HTTP verdict as it was.
* **Stored.** Submit a marker through a form (a POST, and only inside the marker window). Then
  revisit the pages already crawled and see whether the marker is live markup or runs there.

A finding is a true positive only when the marker executes. A sink hit or stored-but-inert markup
is unverified.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Protocol, Sequence
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

from .domain.browser_probe import (
    CHECK_DOM,
    CHECK_REFLECTED,
    CHECK_STORED,
    MODE_DOM,
    MODE_REFLECTED,
    MODE_STORED,
    BrowserObservation,
    MarkerFactory,
    ProbeUrl,
    check_for,
    is_destructive_destination,
    probe_urls,
    render,
    signals_for,
    strongest,
    verdict_for,
)
from .domain.catalog import standards_for
from .domain.entities import Check, CheckMode, Confidence, Evidence, Finding, FindingVerdict, Location, Severity
from .domain.mapping import finding_to_row
from .domain.redaction import redact_text

DEFAULT_MAX_INPUTS = 4
PAUSE_S = 0.2
_TEXT_INPUTS = frozenset({"text", "search", "email", "url", "tel", "number", "", "textarea", "contenteditable"})

_INIT_SCRIPT = r"""
(() => {
  const token = "__TOKEN__";
  if (window.__dastHooks) return;
  window.__dastHooks = true;
  window.__dastWatch = window.__dastWatch || [token];
  window.__dastSinks = window.__dastSinks || [];
  function note(sink, value) {
    var text = "";
    try { text = value == null ? "" : String(value); } catch (e) { return; }
    var watch = window.__dastWatch || [];
    for (var i = 0; i < watch.length; i++) {
      if (watch[i] && text.indexOf(watch[i]) !== -1) { window.__dastSinks.push(sink); return; }
    }
  }
  function wrapSetter(proto, name, sink) {
    var desc = Object.getOwnPropertyDescriptor(proto, name);
    if (!desc || !desc.set) return;
    var setter = desc.set;
    Object.defineProperty(proto, name, {
      configurable: true,
      get: desc.get,
      set: function (value) { note(sink, value); return setter.call(this, value); }
    });
  }
  if (typeof Element !== "undefined") {
    wrapSetter(Element.prototype, "innerHTML", "innerHTML");
    wrapSetter(Element.prototype, "outerHTML", "outerHTML");
    var ia = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function (position, html) {
      note("insertAdjacentHTML", html); return ia.call(this, position, html);
    };
  }
  var write = Document.prototype.write;
  Document.prototype.write = function () {
    note("document.write", Array.prototype.join.call(arguments, ""));
    return write.apply(this, arguments);
  };
  var ev = window.eval;
  window.eval = function (code) { note("eval", code); return ev.call(window, code); };
  var Fn = window.Function;
  window.Function = function () {
    note("Function", Array.prototype.join.call(arguments, ","));
    return Fn.apply(this, arguments);
  };
  var st = window.setTimeout;
  window.setTimeout = function (fn, delay) {
    if (typeof fn === "string") note("setTimeout", fn);
    return st.apply(window, arguments);
  };
  var assign = Location.prototype.assign;
  Location.prototype.assign = function (url) { note("location", url); return assign.call(this, url); };
})();
"""

_FIELDS_JS = """
() => {
  const sel = 'input, textarea, [contenteditable="true"]';
  const skip = new Set(["hidden", "password", "submit", "button", "checkbox", "radio", "file", "image", "reset"]);
  const out = [];
  document.querySelectorAll(sel).forEach((el) => {
    const type = (el.getAttribute("contenteditable") === "true" ? "contenteditable" : (el.getAttribute("type") || el.tagName || "")).toLowerCase();
    if (skip.has(type)) return;
    const form = el.closest("form");
    const index = out.length;
    el.setAttribute("data-dast-probe", String(index));
    if (form && !form.getAttribute("data-dast-form")) form.setAttribute("data-dast-form", String(index));
    out.push({
      selector: '[data-dast-probe="' + index + '"]',
      name: el.getAttribute("name") || el.getAttribute("id") || el.getAttribute("aria-label") || ("field-" + index),
      kind: type || "text",
      in_form: !!form,
      method: form ? (form.getAttribute("method") || "GET").toUpperCase() : "GET",
      action: form ? (form.getAttribute("action") || "") : "",
      form_selector: form ? '[data-dast-form="' + (form.getAttribute("data-dast-form") || index) + '"]' : "",
    });
  });
  return out.slice(0, 20);
}
"""


@dataclass
class ProbeField:
    selector: str
    name: str
    kind: str = "text"
    in_form: bool = False
    method: str = "GET"
    action: str = ""
    form_selector: str = ""


@dataclass
class ProbeHit:
    """What one navigation or submit showed the driver."""

    url: str
    status: int | None = None
    executed: bool = False
    sinks: tuple[str, ...] = ()
    echoed: bool = False  # the server's response body contained the payload verbatim
    dialog: bool = False
    error: str = ""


class ProbeDriver(Protocol):
    def install(self, token: str) -> None: ...

    def open(self, url: str, watch: Sequence[str]) -> ProbeHit: ...

    def fields(self) -> list[ProbeField]: ...

    def submit(self, field: ProbeField, payload: str) -> ProbeHit: ...

    def live_markup(self, payload: str) -> bool: ...


@dataclass
class ProbeReport:
    observations: list[BrowserObservation] = field(default_factory=list)
    rows: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)


def _watch_script(watches: Sequence[str]) -> str:
    return "window.__dastWatch = %s; window.__dastSinks = [];" % json.dumps(list(watches))


class PlaywrightProbeDriver:
    """Real Chromium page. Constructing it does not import Playwright; calling it does, because the
    page object already comes from a Playwright context the crawl opened."""

    def __init__(self, page: Any) -> None:
        self.page = page
        self._dialogs: list[str] = []
        self._installed = False
        try:
            page.on("dialog", self._on_dialog)
        except Exception:  # noqa: BLE001
            pass

    def _on_dialog(self, dialog: Any) -> None:
        try:
            self._dialogs.append(str(dialog.message or ""))
        except Exception:  # noqa: BLE001
            self._dialogs.append("")
        try:
            dialog.dismiss()
        except Exception:  # noqa: BLE001
            pass

    def install(self, token: str) -> None:
        if self._installed:
            return
        self._installed = True
        try:
            self.page.add_init_script(_INIT_SCRIPT.replace("__TOKEN__", token))
        except Exception:  # noqa: BLE001 - a page that cannot take an init script still gets navigated
            pass

    def _arm(self, watch: Sequence[str]) -> None:
        self._dialogs.clear()
        try:
            self.page.add_init_script(_watch_script(watch))
        except Exception:  # noqa: BLE001
            pass

    def _read(self, payload: str, response: Any, url: str) -> ProbeHit:
        executed = False
        sinks: list[str] = []
        echoed = False
        status = None
        try:
            if response is not None:
                status = response.status
                body = response.text() or ""
                echoed = bool(payload and payload in body[:16000])
        except Exception:  # noqa: BLE001
            pass
        try:
            flags = self.page.evaluate(
                """(payload) => Object.keys(window).filter((k) => k.indexOf("__dast_") === 0 && window[k] && payload.indexOf(k.slice(7)) !== -1)""",
                payload,
            )
            executed = bool(flags)
            sinks = list(self.page.evaluate("() => (window.__dastSinks || []).slice()") or [])
        except Exception:  # noqa: BLE001
            pass
        dialog = any(payload and payload in message for message in self._dialogs)
        if dialog:
            executed = True
        try:
            final = self.page.url or url
        except Exception:  # noqa: BLE001
            final = url
        return ProbeHit(url=final, status=status, executed=executed, sinks=tuple(dict.fromkeys(sinks)), echoed=echoed, dialog=dialog)

    def _settle(self) -> None:
        try:
            self.page.wait_for_load_state("domcontentloaded", timeout=8_000)
        except Exception:  # noqa: BLE001
            pass
        try:
            self.page.wait_for_timeout(250)
        except Exception:  # noqa: BLE001
            pass

    def open(self, url: str, watch: Sequence[str]) -> ProbeHit:
        self._arm(watch)
        response = None
        try:
            response = self.page.goto(url, timeout=10_000, wait_until="domcontentloaded")
        except Exception as exc:  # noqa: BLE001
            return ProbeHit(url=url, error=str(exc)[:200])
        self._settle()
        payload = watch[-1] if watch else ""
        return self._read(payload, response, url)

    def fields(self) -> list[ProbeField]:
        try:
            raw = self.page.evaluate(_FIELDS_JS) or []
        except Exception:  # noqa: BLE001
            return []
        out = []
        for item in raw:
            if not isinstance(item, dict) or not item.get("selector"):
                continue
            out.append(
                ProbeField(
                    selector=str(item.get("selector")),
                    name=str(item.get("name") or "field"),
                    kind=str(item.get("kind") or "text"),
                    in_form=bool(item.get("in_form")),
                    method=str(item.get("method") or "GET").upper(),
                    action=str(item.get("action") or ""),
                    form_selector=str(item.get("form_selector") or ""),
                )
            )
        return out

    def submit(self, field: ProbeField, payload: str) -> ProbeHit:
        self._arm([payload])
        try:
            self.page.fill(field.selector, payload, timeout=4_000)
        except Exception as exc:  # noqa: BLE001
            return ProbeHit(url=getattr(self.page, "url", ""), error=str(exc)[:200])
        try:
            if field.in_form and field.method == "POST" and field.form_selector:
                self.page.locator(f"{field.form_selector} [type=submit], {field.form_selector} button").first.click(timeout=3_000)
            else:
                self.page.press(field.selector, "Enter", timeout=3_000)
        except Exception:  # noqa: BLE001 - the fill alone can already have reached a sink
            pass
        self._settle()
        return self._read(payload, None, getattr(self.page, "url", ""))

    def live_markup(self, payload: str) -> bool:
        if not payload:
            return False
        try:
            return bool(self.page.evaluate("(p) => document.documentElement.outerHTML.indexOf(p) !== -1", payload))
        except Exception:  # noqa: BLE001
            return False


# ---- turning observations into finding rows ----------------------------------------------------


def _location(obs: BrowserObservation) -> Location:
    if obs.input_kind in ("query", "fragment-query", "fragment"):
        return Location.QUERY
    if obs.method.upper() == "POST":
        return Location.BODY
    return Location.QUERY


def _target(obs: BrowserObservation) -> str:
    parts = urlsplit(obs.url)
    base = f"{parts.scheme}://{parts.netloc}{parts.path}" if parts.scheme else parts.path or obs.url
    return f"{obs.method.upper()} {base}"


def rows_for(
    observations: Iterable[BrowserObservation],
    checks: Mapping[str, Any],
    secrets: Sequence[str] = (),
    *,
    targets: Mapping[tuple[str, str], str] | None = None,
) -> list[dict[str, Any]]:
    """Finding rows for the strongest observation of each input. `checks` maps a check id to an
    object with `.check` (a catalog `Check`) and `.severity`. `targets` overrides the row target
    for a `(check id, param)` so a browser confirmation merges into the HTTP finding."""
    rows: list[dict[str, Any]] = []
    overrides = targets or {}
    for obs in strongest(observations):
        signals = signals_for(obs)
        verdict = verdict_for(signals)
        if verdict is None:
            continue
        check_id = check_for(obs)
        effective = checks.get(check_id)
        if effective is None:
            continue
        check: Check = effective.check
        confidence = Confidence.HIGH if verdict is FindingVerdict.TRUE_POSITIVE else Confidence.LOW
        excerpt = redact_text(obs.excerpt or signals[0].detail, secrets)
        target = overrides.get((check_id, obs.param), _target(obs))
        finding = Finding(
            check_id=check.check_id,
            severity=Severity(effective.severity.value),
            confidence=confidence,
            verdict=verdict,
            target=target,
            param=obs.param,
            location=_location(obs),
            standards=tuple(standards_for(check)),
            remediation_ref=check.remediation_ref,
            evidence=Evidence("", excerpt, tuple(signals), ""),
        )
        rows.append(
            finding_to_row(
                finding,
                title=f"{check.title} — {obs.param}",
                source=", ".join(s.name for s in signals),
                sink=obs.revisit_url or obs.url,
                verdict_reason=signals[0].detail,
                snippet="\n".join(
                    [
                        f"Check: {check.title}",
                        f"Input: {obs.param} ({obs.input_kind})",
                        f"Marker: {obs.marker_id}",
                        f"Signals: {', '.join(s.name for s in signals)}",
                    ]
                ),
            )
        )
    return rows


# ---- the passes --------------------------------------------------------------------------------


def _set_query(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != name]
    pairs.append((name, value))
    return urlunsplit(parts._replace(query=urlencode(pairs, quote_via=quote, safe="")))


def _id_of(payload: str, token: str) -> str:
    if not payload.startswith(token):
        return token
    digits = []
    for ch in payload[len(token):]:
        if not ch.isdigit():
            break
        digits.append(ch)
    return token + "".join(digits)


def _payload_for(factory: MarkerFactory, template: str = "html") -> tuple[str, str]:
    marker_id = factory.next_id()
    return marker_id, render(template, marker_id)


def _observe(mode: str, url: str, param: str, kind: str, marker_id: str, payload: str, hit: ProbeHit, method: str = "GET") -> BrowserObservation:
    return BrowserObservation(
        mode=mode,
        url=url,
        param=param,
        input_kind=kind,
        marker_id=marker_id,
        payload=payload,
        executed=hit.executed,
        sinks=hit.sinks,
        echoed_by_server=hit.echoed,
        status=hit.status,
        method=method,
        excerpt=hit.error,
    )


def run_probes(
    *,
    pages: Sequence[Mapping[str, Any]],
    reflected: Sequence[Mapping[str, Any]],
    driver: ProbeDriver,
    factory: MarkerFactory,
    checks: Mapping[str, Any],
    marker_window: Callable[[str], Any],
    allow_stored: bool,
    gate: Any | None = None,
    max_pages: int = 15,
    max_inputs: int = DEFAULT_MAX_INPUTS,
    secrets: Sequence[str] = (),
    cancelled: Callable[[], bool] = lambda: False,
    pause: Callable[[], None] | None = None,
    log: Callable[[str], None] = print,
) -> ProbeReport:
    """Run the three passes. `marker_window(token)` is a context manager; it is entered only around
    one stored submit. `pause` spaces probes (the browser guard does not rate-limit them)."""
    report = ProbeReport()
    if cancelled():
        report.summary = {"skipped": "cancelled", "probes": 0, "findings": 0}
        return report
    wanted = [cid for cid in (CHECK_DOM, CHECK_REFLECTED, CHECK_STORED) if cid in checks]
    if not wanted:
        report.summary = {"skipped": "no browser check is enabled", "probes": 0, "findings": 0}
        return report
    driver.install(factory.token)
    observations: list[BrowserObservation] = []
    probes = 0
    submits = 0
    stored_payloads: list[tuple[str, str, str]] = []  # marker id, payload, param
    pause = pause or (lambda: time.sleep(PAUSE_S))
    page_list = [p for p in pages if p.get("url")][:max_pages]

    def blocked(value: str) -> bool:
        if gate is None:
            return False
        result = gate.check_marker(value)
        return not result.ok

    if CHECK_DOM in checks or CHECK_REFLECTED in checks:
        for page in page_list:
            if cancelled():
                break
            url = str(page["url"])
            if is_destructive_destination(url):
                continue
            seen: set[str] = set()
            for probe in probe_urls(url, lambda name: _payload_for(factory)[1], max_params=max_inputs):
                if probe.param in seen or is_destructive_destination(probe.url):
                    continue
                seen.add(probe.param)
                pairs = parse_qsl(urlsplit(probe.url).query, keep_blank_values=True)
                payload_text = pairs[-1][1] if pairs else unquote(probe.url.partition("#")[2])
                marker_id = _id_of(payload_text, factory.token)
                if blocked(payload_text):
                    continue
                hit = driver.open(probe.url, [factory.token, payload_text])
                probes += 1
                observations.append(_observe(MODE_DOM, url, probe.param, probe.kind, marker_id, payload_text, hit))
                pause()
                if probes >= max_pages * max_inputs:
                    break
            if probes >= max_pages * max_inputs:
                break
            try:
                driver.open(url, [factory.token])
            except Exception:  # noqa: BLE001
                pass
            fields = [f for f in driver.fields() if f.kind in _TEXT_INPUTS][:max_inputs]
            for item in fields:
                if cancelled():
                    break
                if item.method == "POST":
                    continue  # stored pass owns POSTs
                marker_id, payload = _payload_for(factory)
                if blocked(payload) or is_destructive_destination(item.action):
                    continue
                hit = driver.submit(item, payload)
                probes += 1
                observations.append(_observe(MODE_DOM, url, item.name, "field", marker_id, payload, hit))
                pause()

    confirm_targets: dict[tuple[str, str], str] = {}
    if CHECK_REFLECTED in checks:
        for hit in reflected:
            if cancelled():
                break
            location = str(hit.get("location") or "")
            param = str(hit.get("param") or "")
            base = str(hit.get("url") or "")
            if location not in ("query", "path") or not param or not base or is_destructive_destination(base):
                continue
            marker_id, payload = _payload_for(factory)
            if blocked(payload):
                continue
            url = _set_query(base, param, payload) if location == "query" else base
            result = driver.open(url, [factory.token, payload])
            probes += 1
            if not result.executed:
                pause()
                continue
            obs = _observe(MODE_REFLECTED, url, param, "query", marker_id, payload, result)
            observations.append(obs)
            if hit.get("target"):
                confirm_targets[(CHECK_REFLECTED, param)] = str(hit["target"])
            pause()

    if allow_stored and CHECK_STORED in checks:
        for page in page_list:
            if cancelled():
                break
            url = str(page["url"])
            if is_destructive_destination(url):
                continue
            try:
                driver.open(url, [factory.token])
            except Exception:  # noqa: BLE001
                continue
            posts = [f for f in driver.fields() if f.kind in _TEXT_INPUTS and f.in_form and f.method == "POST"][:max_inputs]
            for item in posts:
                if cancelled() or submits >= max_inputs * max_pages:
                    break
                action = item.action or url
                if is_destructive_destination(action):
                    log(f"    [browser] skipped a marker submit to {action} (destructive)")
                    continue
                marker_id, payload = _payload_for(factory)
                if blocked(payload):
                    continue
                with marker_window(factory.token):
                    hit = driver.submit(item, payload)
                submits += 1
                probes += 1
                observations.append(_observe(MODE_STORED, url, item.name, "field", marker_id, payload, hit, "POST"))
                stored_payloads.append((marker_id, payload, item.name))
                pause()
        for _, payload, param in stored_payloads:
            if cancelled():
                break
            for page in page_list:
                if cancelled():
                    break
                revisit = str(page["url"])
                if is_destructive_destination(revisit):
                    continue
                result = driver.open(revisit, [factory.token, payload])
                probes += 1
                persisted = (not result.executed) and driver.live_markup(payload)
                if not result.executed and not persisted:
                    continue
                observations.append(
                    BrowserObservation(
                        mode=MODE_STORED, url=revisit, param=param, input_kind="field",
                        marker_id=factory.token, payload=payload, executed=result.executed, sinks=result.sinks,
                        persisted=persisted, status=result.status, revisit_url=revisit, method="GET",
                        excerpt="marker still present on a later page" if persisted else "",
                    )
                )
                pause()

    report.observations = observations
    report.rows = rows_for(observations, checks, secrets, targets=confirm_targets)
    executed = sum(1 for o in observations if o.executed)
    report.summary = {
        "probes": probes,
        "marker_submits": submits,
        "executed": executed,
        "findings": len(report.rows),
        "checks": wanted,
        "skipped": "",
    }
    log(f"[browser] {probes} probe(s), {submits} marker submit(s), {executed} ran in the page, {len(report.rows)} finding(s).")
    return report


def reflected_hits(api_analysis: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """`dast-xss` failures from the HTTP stage, as URLs the browser can replay."""
    hits = []
    for record in api_analysis or []:
        for check in record.get("checks") or []:
            if check.get("check_id") != CHECK_REFLECTED or str(check.get("verdict") or "").upper() != "FAIL":
                continue
            request = check.get("request") or {}
            hits.append(
                {
                    "url": request.get("url") or record.get("url") or "",
                    "param": check.get("target") or request.get("parameter") or "",
                    "location": check.get("location") or request.get("location") or "",
                    "target": record.get("label") or "",
                }
            )
    return hits


def synthetic_checks() -> dict[str, Any]:
    """Stand-ins for a scan that has no rule set (the standalone tool): DOM and reflected on,
    stored off (it is opt-in)."""
    from types import SimpleNamespace

    def one(check_id: str, title: str, ref: str) -> Any:
        check = Check(
            check_id=check_id, title=title, standards={"owasp": ("A03:2021",), "cwe": ("CWE-79",)},
            location=Location.QUERY, detector_signals=("marker_executed_in_browser",),
            base_severity=Severity.MEDIUM, mode=CheckMode.AUTOMATED, remediation_ref=ref,
        )
        return SimpleNamespace(check=check, severity=Severity.MEDIUM)

    return {CHECK_DOM: one(CHECK_DOM, "Cross-site scripting (DOM)", "rem-xss-dom"), CHECK_REFLECTED: one(CHECK_REFLECTED, "Cross-site scripting (reflected)", "rem-xss")}
