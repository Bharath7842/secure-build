"""Browser-side input probing (pure rules): marker payloads, observations and what they prove.

The browser probe types an *inert marker* into page inputs and URL parameters and watches whether
the page ever runs it. Everything that decides what an observation means lives here, with no
Playwright, no clock and no I/O, so the rules are tested without a browser.

Three ideas keep this safe and honest:

* **A marker never does anything.** Every payload only sets a unique `window.__dast_<id>` flag (or
  breaks out of a string so a flag assignment can run). It makes no request, reads no cookie and
  touches no storage. `TEMPLATES` is the complete list; `is_marker_body` is the policy's test that a
  browser POST carries nothing else.
* **Execution is the proof.** `marker_executed_in_browser` (the flag was set by page code) is the only
  signal that makes a `true_positive`. A marker that reached a dangerous sink (`marker_reaches_dom_sink`)
  or survives as live markup on a revisit (`marker_persisted_unescaped`) without running is recorded
  `unverified`: a human should look, the scan has not shown an exploit.
* **Attribution.** Each marker carries a per-scan token plus a counter (`<token><n>`), so a hit names the
  exact input that caused it, and a stored marker can be told apart from anyone else's.
"""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from .entities import DetectorSignal, FindingVerdict
from .guardrail import browser_finding_verdict

# ---- signals ------------------------------------------------------------------------------------

SIGNAL_EXECUTED = "marker_executed_in_browser"
SIGNAL_SINK = "marker_reaches_dom_sink"
SIGNAL_PERSISTED = "marker_persisted_unescaped"
BROWSER_SIGNALS: frozenset[str] = frozenset({SIGNAL_EXECUTED, SIGNAL_SINK, SIGNAL_PERSISTED})
# Only execution proves an issue; the other two never make a true positive on their own.
PROVING_BROWSER_SIGNALS: frozenset[str] = frozenset({SIGNAL_EXECUTED})

# Check ids (entries in the check catalog).
CHECK_REFLECTED = "dast-xss"  # confirmed in the browser when the server echoed the marker back
CHECK_DOM = "dast-xss-dom"
CHECK_STORED = "dast-xss-stored"
BROWSER_CHECK_IDS = (CHECK_DOM, CHECK_STORED)

MODE_DOM, MODE_REFLECTED, MODE_STORED = "dom", "reflected", "stored"
MODES = (MODE_DOM, MODE_REFLECTED, MODE_STORED)

# Sinks the init script instruments. A marker landing in one with markup characters is reported.
SINKS = ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval", "Function", "setTimeout", "location")

# ---- the marker generator and the payload templates -------------------------------------------

# Same logout/delete/reset filter the crawl uses (`nodes/crawl.py`), plus payment flows: a marker
# submit must not log the identity out or start a checkout.
_DESTRUCTIVE_DESTINATION = re.compile(
    r"(?i)(log[\s\-_]?out|sign[\s\-_]?out|delete|deactivate|remove|reset|invalidate|\bdrop\b|payment|checkout|purchase)"
)


def is_destructive_destination(url: str) -> bool:
    """True when a URL looks like logout, deletion or payment. Marker submits never go there."""
    return bool(_DESTRUCTIVE_DESTINATION.search(url or ""))


TOKEN_PREFIX = "dm"
FLAG_PREFIX = "__dast_"
MAX_ID_DIGITS = 6

# `{id}` is replaced by the marker id. Order is the order they are tried. Each one only assigns
# `window.__dast_<id>`; `data:,` as an image source errors without any network request.
TEMPLATES: Mapping[str, str] = {
    "html": '{id}"\'><img src="data:," onerror="window.__dast_{id}=1">',
    "script": "{id}'-(window.__dast_{id}=1)-'",
}
TEMPLATE_ORDER = tuple(TEMPLATES)


def new_token() -> str:
    """A fresh per-scan token (lowercase, letters and digits only)."""
    return TOKEN_PREFIX + secrets.token_hex(4)


class MarkerFactory:
    """Hands out unique marker ids for one scan: `<token><counter>`."""

    def __init__(self, token: str) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9]{3,24}", token or ""):
            raise ValueError("a marker token is 4-25 lowercase letters/digits starting with a letter")
        self.token = token
        self._count = 0

    def next_id(self) -> str:
        self._count += 1
        if self._count >= 10**MAX_ID_DIGITS:
            raise OverflowError("marker id space exhausted")
        return f"{self.token}{self._count}"

    @property
    def issued(self) -> int:
        return self._count


def render(template: str, marker_id: str) -> str:
    """The payload for `template` (a key of `TEMPLATES`) carrying `marker_id`."""
    return TEMPLATES[template].replace("{id}", marker_id)


def flag_name(marker_id: str) -> str:
    return f"{FLAG_PREFIX}{marker_id}"


def has_markup(payload: str) -> bool:
    return any(ch in payload for ch in "<>\"'")


# ---- what a POST may carry (the policy's marker-submit test) -----------------------------------

MAX_BODY_CHARS = 16_000
MAX_COMPANION_CHARS = 512
_FORBIDDEN_COMPANION = re.compile(r"""[<>"'`\x00-\x08\x0b\x0c\x0e-\x1f]""")


def _template_patterns(token: str) -> tuple[re.Pattern[str], ...]:
    out = []
    for template in TEMPLATES.values():
        escaped = re.escape(template).replace(re.escape("{id}"), re.escape(token) + r"\d{1," + str(MAX_ID_DIGITS) + "}")
        out.append(re.compile(rf"\A{escaped}\Z"))
    return tuple(out)


def _body_values(body: Any) -> list[str] | None:
    """Every leaf value of a form-encoded or JSON body; None for anything else (multipart, binary)."""
    if body is None:
        return None
    if isinstance(body, (bytes, bytearray)):
        try:
            body = bytes(body).decode("utf-8")
        except UnicodeDecodeError:
            return None
    if isinstance(body, Mapping):
        return _leaves(body)
    if not isinstance(body, str) or len(body) > MAX_BODY_CHARS:
        return None
    text = body.strip()
    if not text:
        return []
    if text[0] in "{[":
        try:
            return _leaves(json.loads(text))
        except (ValueError, RecursionError):
            return None
    if text.startswith("--") and "Content-Disposition" in text:
        return None  # multipart: not supported, so never allowed
    try:
        return [value for _, value in parse_qsl(text, keep_blank_values=True, max_num_fields=200)]
    except ValueError:
        return None


def _leaves(node: Any, depth: int = 0) -> list[str] | None:
    if depth > 6:
        return None
    if isinstance(node, Mapping):
        out: list[str] = []
        for value in node.values():
            part = _leaves(value, depth + 1)
            if part is None:
                return None
            out.extend(part)
        return out
    if isinstance(node, (list, tuple)):
        out = []
        for value in node:
            part = _leaves(value, depth + 1)
            if part is None:
                return None
            out.extend(part)
        return out
    if node is None or isinstance(node, (bool, int, float)):
        return [str(node)]
    if isinstance(node, str):
        return [node]
    return None


def is_marker_body(body: Any, token: str) -> bool:
    """True when `body` is a form-encoded or JSON body whose only payload-bearing values are exactly
    this scan's marker templates. The remaining ("companion") values are whatever the page itself put
    in the form (a CSRF token, a default): short and free of markup characters. At least one marker
    must be present. Anything else (multipart, binary, a foreign payload, markup in a companion
    field) is not a marker submit and the policy refuses it."""
    if not token:
        return False
    values = _body_values(body)
    if not values:
        return False
    patterns = _template_patterns(token)
    markers = 0
    for value in values:
        if any(p.match(value) for p in patterns):
            markers += 1
            continue
        if len(value) > MAX_COMPANION_CHARS or _FORBIDDEN_COMPANION.search(value):
            return False
    return markers > 0


# ---- probe URLs --------------------------------------------------------------------------------


@dataclass(frozen=True)
class ProbeUrl:
    url: str
    param: str  # the parameter carrying the marker ("#fragment" for a bare fragment probe)
    kind: str  # "query" | "fragment-query" | "fragment"


def _replace_param(pairs: Sequence[tuple[str, str]], index: int, value: str) -> str:
    return urlencode([(k, value if i == index else v) for i, (k, v) in enumerate(pairs)], quote_via=quote, safe="")


def probe_urls(url: str, payload_for: "callable[[str], str]", *, max_params: int = 6) -> list[ProbeUrl]:
    """URLs that carry a marker in each query parameter and in each parameter of a hash-routed
    fragment (`/#/search?q=x`). A page with no parameters at all gets one bare-fragment probe
    (`#<payload>`), which never leaves the browser. `payload_for(param)` returns the payload for a
    parameter, so each probe has its own marker id."""
    parts = urlsplit(url)
    out: list[ProbeUrl] = []
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    for i, (name, _) in enumerate(pairs[:max_params]):
        out.append(ProbeUrl(urlunsplit(parts._replace(query=_replace_param(pairs, i, payload_for(name)))), name, "query"))
    fragment = parts.fragment
    path, sep, frag_query = fragment.partition("?")
    frag_pairs = parse_qsl(frag_query, keep_blank_values=True) if sep else []
    for i, (name, _) in enumerate(frag_pairs[:max_params]):
        new_fragment = f"{path}?{_replace_param(frag_pairs, i, payload_for(name))}"
        out.append(ProbeUrl(urlunsplit(parts._replace(fragment=new_fragment)), name, "fragment-query"))
    if not out:
        base = urlunsplit(parts._replace(fragment=""))
        out.append(ProbeUrl(f"{base}#{quote(payload_for('#fragment'), safe='')}", "#fragment", "fragment"))
    return out


# ---- observations and what they prove ----------------------------------------------------------


@dataclass(frozen=True)
class BrowserObservation:
    """What the browser saw after one marker was typed or loaded."""

    mode: str  # one of MODES
    url: str  # the page the marker was delivered on
    param: str  # the input or parameter that carried it
    input_kind: str  # "query" | "fragment-query" | "fragment" | "field"
    marker_id: str
    payload: str
    executed: bool = False  # page code set window.__dast_<id>
    sinks: tuple[str, ...] = ()  # instrumented sinks that received the marker
    persisted: bool = False  # stored: the marker's markup is live in the DOM of a revisited page
    echoed_by_server: bool = False  # the server's own HTML response carried the payload verbatim
    status: int | None = None
    revisit_url: str = ""  # stored: the page it was seen on
    method: str = "GET"  # the request that delivered it
    excerpt: str = ""  # a short, redacted piece of what the page held
    notes: tuple[str, ...] = field(default_factory=tuple)


def signals_for(obs: BrowserObservation) -> list[DetectorSignal]:
    """The signals an observation supports (most specific first). Execution always wins: a payload that
    ran is reported as that alone, with the sinks it passed through as detail."""
    where = obs.revisit_url or obs.url
    if obs.executed:
        via = f" via {', '.join(obs.sinks)}" if obs.sinks else ""
        return [DetectorSignal(SIGNAL_EXECUTED, f"marker {obs.marker_id} ran in the page{via} ({obs.input_kind} {obs.param!r} on {where})")]
    signals: list[DetectorSignal] = []
    if obs.persisted:
        signals.append(DetectorSignal(SIGNAL_PERSISTED, f"marker {obs.marker_id} is live markup on {where} but did not run"))
    if obs.sinks and has_markup(obs.payload):
        signals.append(DetectorSignal(SIGNAL_SINK, f"marker {obs.marker_id} reached {', '.join(obs.sinks)} but did not run"))
    return signals


def check_for(obs: BrowserObservation) -> str:
    """Which catalog check an observation belongs to. A payload the server itself echoed back that then
    ran is a *reflected* XSS (the browser confirmed the HTTP detector's reflection); one that ran with
    no server echo was assembled client-side, which is DOM-based."""
    if obs.mode == MODE_STORED:
        return CHECK_STORED
    if obs.mode == MODE_REFLECTED or obs.echoed_by_server:
        return CHECK_REFLECTED
    return CHECK_DOM


def verdict_for(signals: Iterable[DetectorSignal]) -> FindingVerdict | None:
    """`true_positive` only for a proving (execution) signal; any other browser signal is
    `unverified`; no signal, no finding. The rule lives in `guardrail.browser_finding_verdict`."""
    return browser_finding_verdict(tuple(signals))


def dedupe_key(obs: BrowserObservation) -> tuple[str, str, str]:
    """`(check, page without its query/fragment, parameter)`: one finding per input however many
    payloads or revisits showed it."""
    parts = urlsplit(obs.url)
    base = f"{parts.scheme}://{parts.netloc}{parts.path}"
    frag_path = parts.fragment.partition("?")[0]
    if frag_path:
        base += f"#{frag_path}"
    return check_for(obs), base, obs.param


def strongest(observations: Iterable[BrowserObservation]) -> list[BrowserObservation]:
    """One observation per `dedupe_key`, the strongest kept (executed beats persisted beats sink)."""

    def rank(o: BrowserObservation) -> int:
        return 3 if o.executed else 2 if o.persisted else 1 if o.sinks else 0

    best: dict[tuple[str, str, str], BrowserObservation] = {}
    for obs in observations:
        key = dedupe_key(obs)
        if key not in best or rank(obs) > rank(best[key]):
            best[key] = obs
    return [best[k] for k in sorted(best)]
