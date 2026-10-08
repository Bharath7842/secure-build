"""Active testing, pure parts (DAST-09-010 .. -050): which inventory entries become targets, how a
model's proposals are filtered and capped, how a request is built from a target plus one test input,
and the shapes the loop passes between its steps.

No I/O and no model here. The engine side (`app/dast/active.py`) runs the steps; this module is what
the steps agree on.

Safety is structural: a request is only built from a `ValidatedTest` (see `validation.py`), parameter
names and values are placed so they cannot change the request's destination (a path value is quoted
into one segment, a header value may not contain line breaks, restricted headers are refused), and
the scope check still applies to whatever URL results.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from .entities import Check, CheckMode, CheckVerdict, DetectorSignal, Endpoint, Location, ResponseSnapshot
from .browser_probe import is_destructive_destination
from .detectors import BROWSER_SIGNALS, DETECTORS
from .guardrail import GuardrailOutcome
from .validation import ValidatedTest

# ---- which checks the model-driven loop may run ------------------------------------------------

# Signals that need something other than one baseline/test pair from one identity: the authorization
# stage (two identities) and the OAST flow own those checks.
# Browser-probe signals are proved in the page, not by an HTTP response pair, so the active loop
# never sends a request in order to raise one.
_NON_LOOP_SIGNALS = frozenset({"auth_boundary_crossed", "oast_callback_received"}) | BROWSER_SIGNALS
_LOOP_SIGNALS = frozenset(DETECTORS) - _NON_LOOP_SIGNALS

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def loop_signals(check: Check) -> list[str]:
    """The detector names the loop should run for `check`, in registry order."""
    return [name for name in DETECTORS if name in check.detector_signals and name in _LOOP_SIGNALS]


def is_loop_check(check: Check, mode: CheckMode) -> bool:
    """A check the construct/test loop runs: automated or explicitly opted-in, active (not
    passive), able to be proven by a response-pair detector."""
    return (not check.passive) and mode is not CheckMode.ASSIST_ONLY and bool(loop_signals(check))


# ---- targets ------------------------------------------------------------------------------------

_KIND_RANK = {"api": 0, "form": 1, "page": 2}
SAMPLE_PATH_VALUE = "1"
_PLACEHOLDER = re.compile(r"\{([^{}/]*)\}")


def target_label(endpoint: Endpoint) -> str:
    """`GET http://host/api/x` when a concrete URL is known, else `GET /api/x`."""
    dest = (endpoint.url or endpoint.path_template).partition("#")[0].partition("?")[0]
    return f"{endpoint.method.upper()} {dest}"


def is_testable(endpoint: Endpoint) -> bool:
    """An API operation, a form, or a page that takes parameters; never a static asset, a GraphQL
    operation pseudo-path, a logout/deletion/payment-shaped endpoint (attacking it can tear down
    the identity's own session or trigger a real side effect), or an entry with no URL to send to."""
    if endpoint.kind == "asset" or not endpoint.url or "#" in endpoint.path_template:
        return False
    if is_destructive_destination(endpoint.url or endpoint.path_template):
        return False
    if endpoint.kind == "page":
        return bool(endpoint.parameters)
    return True


def order_targets(endpoints: Iterable[Endpoint]) -> list[Endpoint]:
    """Deterministic order, most valuable first (APIs, then forms, then parameterised pages), so a
    cap on the number of targets keeps the important ones."""
    return sorted(
        (e for e in endpoints if is_testable(e)),
        key=lambda e: (_KIND_RANK.get(e.kind, 3), e.path_template, e.method),
    )


def concrete_url(endpoint: Endpoint) -> str:
    """The endpoint's example URL with every `{placeholder}` filled by an observed value (or `1`)."""
    values = {p.name: (p.observed_values[0] if p.observed_values else "") for p in endpoint.parameters if p.location is Location.PATH}
    parts = urlsplit(endpoint.url)
    path = _PLACEHOLDER.sub(lambda m: quote(values.get(m.group(1)) or SAMPLE_PATH_VALUE, safe=""), parts.path)
    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))


# ---- proposals ----------------------------------------------------------------------------------

LOCATIONS = ("query", "path", "header", "body")
MAX_INPUT_CHARS = 200


@dataclass(frozen=True)
class TestProposal:
    __test__ = False  # not a pytest class, whatever imports it
    """What the model (or the fallback) suggests: not yet validated, not yet sendable."""

    check_id: str
    parameter: str
    location: str
    input: str
    expected_signal: str = ""
    control_input: str = ""


def parse_proposals(reply: Mapping[str, Any] | None) -> tuple[list[TestProposal], int]:
    """`(proposals, malformed)` from a `construct` reply. Accepts the older `target`/`payload`
    spellings; an entry missing its check, parameter or input, or with an oversized input, is
    counted as malformed and dropped."""
    proposals: list[TestProposal] = []
    malformed = 0
    for raw in (reply or {}).get("tests") or []:
        if not isinstance(raw, Mapping):
            malformed += 1
            continue
        check_id = str(raw.get("check_id") or raw.get("check") or "").strip()
        parameter = str(raw.get("parameter") or raw.get("param") or raw.get("target") or "").strip()
        value = raw.get("input", raw.get("probe", raw.get("payload")))
        location = str(raw.get("location") or "query").strip().lower()
        if not check_id or not parameter or value is None or location not in LOCATIONS or len(str(value)) > MAX_INPUT_CHARS:
            malformed += 1
            continue
        proposals.append(
            TestProposal(check_id, parameter, location, str(value), str(raw.get("expected_signal") or "").strip(), str(raw.get("control_input") or ""))
        )
    return proposals, malformed


@dataclass(frozen=True)
class Construction:
    """What the `construct` step returned for one target."""

    proposals: tuple[TestProposal, ...] = ()
    failed: bool = False  # the model could not help (provider error, unusable reply)
    malformed: int = 0  # entries dropped for being unusable
    raw: int = 0  # how many entries the model returned at all


@dataclass(frozen=True)
class Selection:
    kept: tuple[TestProposal, ...]
    unknown_check: int  # check id not in the effective rule set: dropped, counted
    over_cap: int  # valid, but beyond the per-target cap


def select_proposals(
    proposals: Sequence[TestProposal],
    allowed: Mapping[str, Any],
    cap: int,
    *,
    resolve=lambda check_id: check_id,
    severity_of=lambda check_id: "MEDIUM",
) -> Selection:
    """Drop proposals naming a check outside `allowed` (a check id -> anything mapping; the model's
    ids are resolved through `resolve` for aliases), then keep the `cap` highest-priority ones:
    higher check severity first, model order within a severity. Duplicates (same check, parameter,
    location and input) are dropped silently."""
    kept: list[tuple[int, int, TestProposal]] = []
    unknown = 0
    seen: set[tuple[str, str, str, str]] = set()
    for index, proposal in enumerate(proposals):
        check_id = resolve(proposal.check_id)
        if check_id not in allowed:
            unknown += 1
            continue
        key = (check_id, proposal.parameter, proposal.location, proposal.input)
        if key in seen:
            continue
        seen.add(key)
        normalized = TestProposal(check_id, proposal.parameter, proposal.location, proposal.input, proposal.expected_signal, proposal.control_input)
        kept.append((SEVERITY_ORDER.get(severity_of(check_id), 5), index, normalized))
    kept.sort(key=lambda item: (item[0], item[1]))
    cap = max(0, cap)
    return Selection(tuple(p for _, _, p in kept[:cap]), unknown, max(0, len(kept) - cap))


def fallback_proposals(target: Endpoint, checks: Sequence[Check], cap: int) -> list[TestProposal]:
    """Conservative proposals for when the model could not help: for each applicable check, one test
    whose input is the parameter's own observed value, so the request is a baseline repeat and the
    detectors can still notice what the target does on its own (a 500 with a stack trace, an error
    that appears only on a second call). No attack string is invented here."""
    out: list[TestProposal] = []
    for check in checks:
        if check.mode is CheckMode.ASSIST_ONLY or check.passive:
            continue
        allowed = {str(v) for v in (check.applies_to.get("locations") or [check.location.value])}
        methods = {str(m).upper() for m in (check.applies_to.get("methods") or [])}
        if methods and target.method.upper() not in methods:
            continue
        for param in target.parameters:
            if param.location.value in allowed and param.location.value in LOCATIONS:
                value = param.observed_values[0] if param.observed_values else ""
                out.append(TestProposal(check.check_id, param.name, param.location.value, value, "behaviour that differs from the baseline"))
                break
        if len(out) >= cap:
            break
    return out[: max(0, cap)]


# ---- building requests --------------------------------------------------------------------------


@dataclass(frozen=True)
class BuiltRequest:
    method: str
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    body: Any = None  # dict (JSON), str (form-encoded / raw) or None


def _sample_json(body_sample: str | None) -> dict | None:
    if not body_sample:
        return None
    try:
        data = json.loads(body_sample)
    except ValueError:
        return None
    return dict(data) if isinstance(data, dict) else None


def _baseline_body(endpoint: Endpoint) -> tuple[Any, str]:
    """`(body, content_type)` of the endpoint's normal request: the recorded body shape when there
    is one, else one assembled from its body parameters' observed values (hidden and CSRF fields
    included, so a test does not fail only for a missing token)."""
    sample = _sample_json(endpoint.body_sample)
    if sample is not None:
        return sample, "application/json"
    if endpoint.body_sample and "=" in endpoint.body_sample and "{" not in endpoint.body_sample:
        return dict(parse_qsl(endpoint.body_sample, keep_blank_values=True)), "application/x-www-form-urlencoded"
    fields = {p.name: (p.observed_values[0] if p.observed_values else "") for p in endpoint.parameters if p.location is Location.BODY}
    if fields:
        form = endpoint.kind == "form" or "form" in (endpoint.content_type or "")
        return fields, "application/x-www-form-urlencoded" if form else "application/json"
    return None, ""


def build_request(endpoint: Endpoint, test: ValidatedTest | None = None, *, control: bool = False) -> BuiltRequest:
    """The endpoint's normal request (`test=None`: the baseline), or the same request with one input
    placed per the test's location. `control=True` uses the test's control value instead."""
    if test is not None and not isinstance(test, ValidatedTest):
        raise TypeError("only a ValidatedTest may be turned into a request")
    method = endpoint.method.upper()
    parts = urlsplit(concrete_url(endpoint))
    path, query = parts.path, parse_qsl(parts.query, keep_blank_values=True)
    for param in endpoint.parameters:  # a baseline carries the observed query values
        if param.location is Location.QUERY and param.name not in dict(query):
            query.append((param.name, param.observed_values[0] if param.observed_values else ""))
    headers: dict[str, str] = {}
    body, content_type = _baseline_body(endpoint)
    if isinstance(body, dict):
        body = dict(body)

    if test is not None:
        value = test.control_value if control else test.value
        if test.location == "query":
            query = [(k, v) for k, v in query if k != test.parameter] + [(test.parameter, value)]
        elif test.location == "path":
            segments = [s for s in endpoint.path_template.split("/")]
            placeholder = "{" + test.parameter + "}"
            if placeholder in segments:
                concrete = parts.path.split("/")
                index = segments.index(placeholder)
                if index < len(concrete):
                    concrete[index] = quote(value, safe="")
                    path = "/".join(concrete)
            else:  # no such placeholder: the input becomes one extra path segment
                path = path.rstrip("/") + "/" + quote(value, safe="")
        elif test.location == "header":
            headers[test.parameter] = value
        elif test.location == "body":
            if not isinstance(body, dict):
                body, content_type = {}, content_type or "application/json"
            body[test.parameter] = value
    if body is not None and content_type:
        headers["Content-Type"] = content_type
        if content_type == "application/x-www-form-urlencoded":
            body = urlencode(body)
    url = urlunsplit((parts.scheme, parts.netloc, path, urlencode(query), ""))
    return BuiltRequest(method, url, headers, body)


# ---- what the steps pass around -----------------------------------------------------------------


@dataclass(frozen=True)
class Exchange:
    """One request's outcome as the loop sees it. `error` is set when nothing usable came back:
    `request not sent: <reason>` when the guard refused it, else a transport failure."""

    status: int | None = None
    length: int = 0
    body: str = ""
    headers: Mapping[str, str] = field(default_factory=dict)
    elapsed_ms: float = 0.0
    error: str = ""
    audit_seq: int | None = None
    samples_ms: tuple[float, ...] = ()  # repeated timings, for time-based checks
    control: "Exchange | None" = None  # the response to the logically-false variant, when one was sent

    @property
    def sent(self) -> bool:
        return not self.error.startswith("request not sent")

    @property
    def usable(self) -> bool:
        return not self.error and self.status is not None

    def snapshot(self) -> ResponseSnapshot:
        return ResponseSnapshot(self.status, self.length, self.body, dict(self.headers), self.elapsed_ms)


@dataclass(frozen=True)
class Advice:
    """The model's opinion on one test. Advisory only: the guardrail decides."""

    verdict: CheckVerdict
    finding: str = ""
    severity: str = ""
    confidence: str = ""
    evidence: str = ""


@dataclass
class TestRecord:
    __test__ = False
    check_id: str
    parameter: str
    location: str
    input: str
    expected_signal: str
    baseline: Exchange | None = None
    result: Exchange | None = None
    signals: tuple[DetectorSignal, ...] = ()
    advice: Advice | None = None
    outcome: GuardrailOutcome | None = None
    note: str = ""

    @property
    def verdict(self) -> CheckVerdict:
        return self.outcome.verdict if self.outcome else CheckVerdict.PASS

    @property
    def sent(self) -> bool:
        return self.result is not None and self.result.sent


@dataclass
class TargetOutcome:
    label: str
    endpoint: Endpoint
    records: list[TestRecord] = field(default_factory=list)
    dropped_unknown: int = 0
    dropped_unsafe: int = 0
    dropped_malformed: int = 0
    over_cap: int = 0
    used_fallback: bool = False
    skipped: str = ""  # why nothing ran: "not tested: safe mode", "no applicable checks", ...
    error: str = ""  # an exception the target's run raised (recorded, the stage continues)
    verdict: CheckVerdict = CheckVerdict.PASS

    @property
    def tests_sent(self) -> int:
        return sum(1 for r in self.records if r.sent)


@dataclass
class StageResult:
    outcomes: list[TargetOutcome] = field(default_factory=list)
    targets_total: int = 0
    targets_capped: int = 0  # eligible targets left untested by the targets cap
    cancelled: bool = False
    session_lost_reason: str = ""  # set once the stage stopped because the identity's session died

    def tests_sent(self) -> int:
        return sum(o.tests_sent for o in self.outcomes)
