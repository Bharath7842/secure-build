"""The detector library (DAST-04-020, -030): pure comparisons of a baseline response
against a test response.

A detector observes and never judges: it returns zero or more named signals and has
no side effects, no clock, no randomness and no I/O. The guardrail (`guardrail.py`)
decides what a signal is worth. Every detector tolerates truncated bodies, non-text
content and missing fields without raising, because it runs on whatever a hostile or
broken target sent back.

All detectors share one signature, `(baseline, test, ctx) -> list[DetectorSignal]`, and
one registry (`DETECTORS`), whose key set is the vocabulary a check may name as a proving
signal (the catalog loader validates against `signal_names()`).

The inputs a detector needs beyond the two responses travel in `DetectionContext`:
the payload that was sent (reflection), timing samples (time_delta) and a control
response (boolean_divergence). A detector that needs something the context lacks
returns no signal rather than guessing.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Callable, Mapping, Sequence

from . import detector_patterns as P
from .entities import DetectorSignal, ResponseSnapshot
from .tls import TLS_SIGNAL_NAMES


@dataclass(frozen=True)
class DetectionContext:
    payload: str = ""  # the input the test request carried (reflection check)
    baseline_ms: Sequence[float] = ()  # repeated timings of the baseline request
    test_ms: Sequence[float] = ()  # repeated timings of the test request
    time_threshold_ms: float = P.DEFAULT_TIME_THRESHOLD_MS
    control: ResponseSnapshot | None = None  # response to the logically-false variant
    length_tolerance: float = P.BODY_LENGTH_TOLERANCE


DetectorFn = Callable[[ResponseSnapshot, ResponseSnapshot, DetectionContext], "list[DetectorSignal]"]

_EMPTY = DetectionContext()


# ---- defensive accessors ----------------------------------------------------------------------


def _text(response: ResponseSnapshot | None) -> str:
    """Body excerpt as text; "" for a missing, non-text or binary body."""
    if response is None:
        return ""
    body: Any = getattr(response, "body_excerpt", "")
    if body is None:
        return ""
    if isinstance(body, (bytes, bytearray)):
        body = bytes(body).decode("utf-8", errors="replace")
    elif not isinstance(body, str):
        try:
            body = str(body)
        except Exception:  # noqa: BLE001 - an object with a broken __str__ is still just "no text"
            return ""
    if body.count("\x00") > 0:  # binary content: text patterns on it are meaningless
        return ""
    return body


def _status(response: ResponseSnapshot | None) -> int | None:
    status = getattr(response, "status", None)
    return status if isinstance(status, int) and not isinstance(status, bool) else None


def _length(response: ResponseSnapshot | None) -> int:
    length = getattr(response, "length", None)
    if isinstance(length, int) and not isinstance(length, bool) and length >= 0:
        return length
    return len(_text(response))


def _header(response: ResponseSnapshot | None, name: str) -> str:
    headers = getattr(response, "headers", None) or {}
    try:
        for key, value in headers.items():
            if str(key).lower() == name:
                return str(value)
    except Exception:  # noqa: BLE001
        return ""
    return ""


def _quote(text: str) -> str:
    text = " ".join(text.split())
    return text[: P.MAX_EXCERPT_CHARS]


@lru_cache(maxsize=None)
def _compile(patterns: tuple[str, ...]) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p, re.IGNORECASE | re.MULTILINE) for p in patterns)


def _first_new_match(patterns: tuple[str, ...], baseline: str, test: str) -> str | None:
    """First pattern text present in `test` whose pattern does not also match `baseline`."""
    for pattern in _compile(patterns):
        found = pattern.search(test)
        if found and not pattern.search(baseline):
            return found.group(0)
    return None


# ---- injection and leakage signals (DAST-04-020) -----------------------------------------------


def db_error_surfaced(baseline: ResponseSnapshot, test: ResponseSnapshot, ctx: DetectionContext = _EMPTY) -> list[DetectorSignal]:
    match = _first_new_match(P.DB_ERROR_PATTERNS, _text(baseline), _text(test))
    return [DetectorSignal("db_error_surfaced", _quote(match))] if match else []


def stack_trace_leaked(baseline: ResponseSnapshot, test: ResponseSnapshot, ctx: DetectionContext = _EMPTY) -> list[DetectorSignal]:
    match = _first_new_match(P.STACK_TRACE_PATTERNS, _text(baseline), _text(test))
    return [DetectorSignal("stack_trace_leaked", _quote(match))] if match else []


def command_output_marker(baseline: ResponseSnapshot, test: ResponseSnapshot, ctx: DetectionContext = _EMPTY) -> list[DetectorSignal]:
    match = _first_new_match(P.COMMAND_OUTPUT_PATTERNS, _text(baseline), _text(test))
    return [DetectorSignal("command_output_marker", _quote(match))] if match else []


_HTML_SPECIAL = re.compile(r"""[<>"'`]""")


def file_disclosure_marker(baseline: ResponseSnapshot, test: ResponseSnapshot, ctx: DetectionContext = _EMPTY) -> list[DetectorSignal]:
    """The content of a file a path-traversal / local-file-include payload reached, not the
    page the endpoint normally renders."""
    match = _first_new_match(P.FILE_DISCLOSURE_PATTERNS, _text(baseline), _text(test))
    return [DetectorSignal("file_disclosure_marker", _quote(match))] if match else []


def nosql_error_surfaced(baseline: ResponseSnapshot, test: ResponseSnapshot, ctx: DetectionContext = _EMPTY) -> list[DetectorSignal]:
    match = _first_new_match(P.NOSQL_ERROR_PATTERNS, _text(baseline), _text(test))
    return [DetectorSignal("nosql_error_surfaced", _quote(match))] if match else []


def ldap_error_surfaced(baseline: ResponseSnapshot, test: ResponseSnapshot, ctx: DetectionContext = _EMPTY) -> list[DetectorSignal]:
    match = _first_new_match(P.LDAP_ERROR_PATTERNS, _text(baseline), _text(test))
    return [DetectorSignal("ldap_error_surfaced", _quote(match))] if match else []


def xpath_error_surfaced(baseline: ResponseSnapshot, test: ResponseSnapshot, ctx: DetectionContext = _EMPTY) -> list[DetectorSignal]:
    match = _first_new_match(P.XPATH_ERROR_PATTERNS, _text(baseline), _text(test))
    return [DetectorSignal("xpath_error_surfaced", _quote(match))] if match else []


_TEMPLATE_EXPR = re.compile(P.TEMPLATE_EXPRESSION_PATTERN, re.IGNORECASE)


def template_expression_evaluated(baseline: ResponseSnapshot, test: ResponseSnapshot, ctx: DetectionContext = _EMPTY) -> list[DetectorSignal]:
    """`ctx.payload` is a template expression like `{{7*7}}` wrapping two small integers; this
    fires when the response contains their *product* (evaluation) rather than the literal
    expression (reflection). The baseline must not already contain that product by coincidence,
    and the raw markup surviving into the test response means it was never evaluated."""
    payload = (ctx.payload or "").strip()
    match = _TEMPLATE_EXPR.match(payload)
    if not match:
        return []
    a, b = int(match.group(1)), int(match.group(2))
    if a > 999 or b > 999:  # a probe, not an arbitrary calculator
        return []
    product = str(a * b)
    body = _text(test)
    if product not in body or product in _text(baseline) or payload in body:
        return []
    return [DetectorSignal("template_expression_evaluated", f"{payload} evaluated to {product}")]


_ABSOLUTE_URL = re.compile(P.ABSOLUTE_URL_PATTERN, re.IGNORECASE)


def open_redirect_location(baseline: ResponseSnapshot, test: ResponseSnapshot, ctx: DetectionContext = _EMPTY) -> list[DetectorSignal]:
    """`ctx.payload` is an absolute, off-origin URL supplied as a redirect-target parameter;
    this fires when a redirect response's `Location` sends the browser to that same URL."""
    payload = (ctx.payload or "").strip()
    if not payload or not _ABSOLUTE_URL.match(payload):
        return []
    status = _status(test)
    if status is None or not (300 <= status < 400):
        return []
    location = _header(test, "location").strip()
    if not location:
        return []
    if location.rstrip("/") == payload.rstrip("/") or location.startswith(payload):
        return [DetectorSignal("open_redirect_location", f"Location: {_quote(location)}")]
    return []


_XXE_SHAPE = re.compile(r"<!DOCTYPE|<!ENTITY", re.IGNORECASE)
_XXE_INTERNAL = re.compile(r"""<!ENTITY\s+\w+\s+["']([^"']{4,40})["']""", re.IGNORECASE)
_PROTO = re.compile(r"__proto__|constructor\.prototype", re.IGNORECASE)


def xxe_entity_resolved(baseline: ResponseSnapshot, test: ResponseSnapshot, ctx: DetectionContext = _EMPTY) -> list[DetectorSignal]:
    """In-band XXE: the payload declared an entity, and the response either contains a
    file the payload should not have reached, an error that says an external entity was
    loaded, or the replacement text of an internal entity (the declaration itself is not
    echoed, so the parser expanded it)."""
    payload = ctx.payload or ""
    if not _XXE_SHAPE.search(payload):
        return []
    match = _first_new_match(P.FILE_DISCLOSURE_PATTERNS + P.XXE_RESOLVED_PATTERNS, _text(baseline), _text(test))
    if match:
        return [DetectorSignal("xxe_entity_resolved", _quote(match))]
    internal = _XXE_INTERNAL.search(payload)
    if internal:
        marker = internal.group(1)
        body = _text(test)
        if marker in body and marker not in _text(baseline) and "<!ENTITY" not in body.upper():
            return [DetectorSignal("xxe_entity_resolved", f"internal entity expanded to {_quote(marker)}")]
    return []


def parameter_pollution_selected(baseline: ResponseSnapshot, test: ResponseSnapshot, ctx: DetectionContext = _EMPTY) -> list[DetectorSignal]:
    """`ctx.payload` is the extra value sent as a duplicate parameter. Fires when the
    server still answers in the same status class and the response now contains that
    value, which the baseline did not: the duplicate was selected rather than rejected."""
    payload = (ctx.payload or "").strip()
    if len(payload) < 4 or _HTML_SPECIAL.search(payload):
        return []
    body = _text(test)
    if payload not in body or payload in _text(baseline):
        return []
    if _status_class(_status(baseline)) != _status_class(_status(test)):
        return []
    return [DetectorSignal("parameter_pollution_selected", f"duplicate parameter value selected ({_quote(payload)})")]


def prototype_pollution_applied(baseline: ResponseSnapshot, test: ResponseSnapshot, ctx: DetectionContext = _EMPTY) -> list[DetectorSignal]:
    """`ctx.payload` names `__proto__` or `constructor.prototype`. Fires when the test
    JSON grew a key that the payload names and the baseline JSON did not have."""
    payload = ctx.payload or ""
    if not _PROTO.search(payload):
        return []
    keys_b, keys_t = _json_keys(_text(baseline)), _json_keys(_text(test))
    if keys_t is None:
        return []
    fresh = keys_t - (keys_b or frozenset())
    named = [key for key in sorted(fresh) if key and key in payload]
    if not named:
        return []
    return [DetectorSignal("prototype_pollution_applied", f"new JSON key(s) from the payload: {', '.join(named[:5])}")]


def csrf_not_enforced(baseline: ResponseSnapshot, test: ResponseSnapshot, ctx: DetectionContext = _EMPTY) -> list[DetectorSignal]:
    """`baseline` is the state-changing request's own successful response with its real CSRF
    token; `test` is the same request with that token missing or replaced by an invalid value.
    A test response that still succeeds, materially equivalent to the baseline, proves the token
    was never checked. Mirrors `auth_boundary_crossed`'s shape (equivalence is the problem, not
    divergence) applied to token presence instead of identity."""
    sb, st = _status(baseline), _status(test)
    if sb is None or st is None or not (200 <= sb < 300) or not (200 <= st < 300):
        return []
    if _length(baseline) == 0 or _length(test) == 0:
        return []
    if not materially_equivalent(baseline, test, ctx.length_tolerance):
        return []
    return [DetectorSignal("csrf_not_enforced", f"status {st} with no valid CSRF token, matching the token-present baseline")]


def input_reflected_unescaped(baseline: ResponseSnapshot, test: ResponseSnapshot, ctx: DetectionContext = _EMPTY) -> list[DetectorSignal]:
    """The payload comes back byte-for-byte, markup characters and all, where the baseline
    did not carry it. A payload with no markup characters proves nothing about escaping, and
    an HTML- or JSON-escaped echo no longer contains the raw payload, so neither fires."""
    payload = ctx.payload or ""
    if not payload or not _HTML_SPECIAL.search(payload):
        return []
    body = _text(test)
    if payload in body and payload not in _text(baseline):
        return [DetectorSignal("input_reflected_unescaped", f"payload reflected verbatim ({len(payload)} chars)")]
    return []


# ---- divergence, timing and authorization boundary (DAST-04-030) -------------------------------


def _status_class(status: int | None) -> int | None:
    return status // 100 if status is not None else None


def lengths_equivalent(a: int, b: int, tolerance: float = P.BODY_LENGTH_TOLERANCE) -> bool:
    """Same size within `tolerance` (relative) or the absolute floor, whichever is looser."""
    difference = abs(a - b)
    if difference <= P.BODY_LENGTH_TOLERANCE_FLOOR:
        return True
    return difference <= tolerance * max(a, b)


def _json_keys(text: str) -> frozenset[str] | None:
    try:
        parsed = json.loads(text)
    except (ValueError, RecursionError):
        return None
    if isinstance(parsed, dict):
        return frozenset(str(k) for k in parsed)
    if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
        return frozenset(str(k) for k in parsed[0])
    return frozenset()


def materially_equivalent(a: ResponseSnapshot, b: ResponseSnapshot, tolerance: float = P.BODY_LENGTH_TOLERANCE) -> bool:
    """Same status class, similar size and, for JSON bodies, similar top-level shape.

    Two empty bodies are *not* equivalent in this sense (see `auth_boundary_crossed`): an
    empty 200 says nothing about what either caller was allowed to see."""
    if _status_class(_status(a)) != _status_class(_status(b)) or _status(a) is None:
        return False
    if not lengths_equivalent(_length(a), _length(b), tolerance):
        return False
    keys_a, keys_b = _json_keys(_text(a)), _json_keys(_text(b))
    if keys_a is not None and keys_b is not None and (keys_a or keys_b):
        union = keys_a | keys_b
        return len(keys_a & keys_b) / len(union) >= P.JSON_KEY_OVERLAP_MIN
    return True


def status_length_divergence(baseline: ResponseSnapshot, test: ResponseSnapshot, ctx: DetectionContext = _EMPTY) -> list[DetectorSignal]:
    """Direction-aware: a response that becomes *more* restrictive than the baseline (e.g. a
    malicious/malformed test input correctly refused, 2xx baseline -> 4xx test) is proof the
    target behaved safely and never fires alone. Only a server error (5xx) or the test being
    accepted where the baseline was refused (non-2xx baseline -> 2xx test) counts as divergence
    across a status-class change; a same-class difference still falls through to the length
    comparison, unchanged."""
    sb, st = _status(baseline), _status(test)
    if sb is None or st is None:
        return []
    cb, ct = _status_class(sb), _status_class(st)
    if cb != ct:
        if ct == 5 or (cb != 2 and ct == 2):
            return [DetectorSignal("status_length_divergence", f"status {sb} -> {st}")]
        return []
    lb, lt = _length(baseline), _length(test)
    if not lengths_equivalent(lb, lt, ctx.length_tolerance):
        return [DetectorSignal("status_length_divergence", f"length {lb} -> {lt}")]
    return []


def boolean_divergence(baseline: ResponseSnapshot, test: ResponseSnapshot, ctx: DetectionContext = _EMPTY) -> list[DetectorSignal]:
    """A "true" variant behaves like the baseline while a "false" variant (`ctx.control`)
    does not: the input is steering the server's logic. Needs the control response."""
    control = ctx.control
    if control is None:
        return []
    if not materially_equivalent(baseline, test, ctx.length_tolerance):
        return []
    if materially_equivalent(baseline, control, ctx.length_tolerance):
        return []
    return [
        DetectorSignal(
            "boolean_divergence",
            f"true variant matched the baseline; false variant differed (status {_status(control)}, length {_length(control)})",
        )
    ]


def time_delta(baseline: ResponseSnapshot, test: ResponseSnapshot, ctx: DetectionContext = _EMPTY) -> list[DetectorSignal]:
    """Median test latency exceeds median baseline latency by at least the threshold, over
    at least `MIN_TIMING_SAMPLES` samples each. Uses supplied durations only; it never
    measures time itself."""
    base = [float(x) for x in ctx.baseline_ms if _is_number(x)]
    tests = [float(x) for x in ctx.test_ms if _is_number(x)]
    if len(base) < P.MIN_TIMING_SAMPLES or len(tests) < P.MIN_TIMING_SAMPLES:
        return []
    delta = _median(tests) - _median(base)
    # Every test sample must be slower than the slowest baseline one, so a single outlier
    # cannot carry the median.
    if delta >= ctx.time_threshold_ms and min(tests) > max(base):
        return [DetectorSignal("time_delta", f"median +{delta:.0f} ms over {len(tests)} samples")]
    return []


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value == value and value >= 0


def _median(values: Sequence[float]) -> float:
    ordered = sorted(values)
    mid = len(ordered) // 2
    return ordered[mid] if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) / 2


def _no_response_signal(name: str):
    """Browser-stage signals are not visible in an HTTP response pair. The functions stay in the
    registry so a check may name them; the browser probe emits the real observations itself."""

    def detector(baseline: ResponseSnapshot, test: ResponseSnapshot, ctx: DetectionContext = _EMPTY) -> list[DetectorSignal]:
        return []

    detector.__name__ = name
    return detector


marker_executed_in_browser = _no_response_signal("marker_executed_in_browser")
marker_reaches_dom_sink = _no_response_signal("marker_reaches_dom_sink")
marker_persisted_unescaped = _no_response_signal("marker_persisted_unescaped")


def auth_boundary_crossed(baseline: ResponseSnapshot, test: ResponseSnapshot, ctx: DetectionContext = _EMPTY) -> list[DetectorSignal]:
    """`baseline` is what the higher-privilege identity received, `test` what a lower-privilege
    or anonymous identity received for the same request. Fires when the lower one got a
    successful, materially equivalent response.

    401/403 (and any non-2xx) never fire. An empty body on either side never fires either: an
    empty 200 is consistent with "allowed to call it, nothing to see", so equivalence of nothing
    is not a boundary crossing (documented edge case, covered by a test)."""
    sb, st = _status(baseline), _status(test)
    if sb is None or st is None or not (200 <= sb < 300) or not (200 <= st < 300):
        return []
    if _length(baseline) == 0 or _length(test) == 0:
        return []
    if not materially_equivalent(baseline, test, ctx.length_tolerance):
        return []
    return [DetectorSignal("auth_boundary_crossed", f"status {st} with a body equivalent to the higher-privilege response")]


# ---- registry ---------------------------------------------------------------------------------

DETECTORS: Mapping[str, DetectorFn] = {
    "db_error_surfaced": db_error_surfaced,
    "input_reflected_unescaped": input_reflected_unescaped,
    "command_output_marker": command_output_marker,
    "stack_trace_leaked": stack_trace_leaked,
    "boolean_divergence": boolean_divergence,
    "time_delta": time_delta,
    "status_length_divergence": status_length_divergence,
    "auth_boundary_crossed": auth_boundary_crossed,
    "file_disclosure_marker": file_disclosure_marker,
    "nosql_error_surfaced": nosql_error_surfaced,
    "ldap_error_surfaced": ldap_error_surfaced,
    "xpath_error_surfaced": xpath_error_surfaced,
    "template_expression_evaluated": template_expression_evaluated,
    "open_redirect_location": open_redirect_location,
    "csrf_not_enforced": csrf_not_enforced,
    "xxe_entity_resolved": xxe_entity_resolved,
    "parameter_pollution_selected": parameter_pollution_selected,
    "prototype_pollution_applied": prototype_pollution_applied,
    # Emitted by the browser probe, never by comparing two HTTP responses (the functions return []).
    "marker_executed_in_browser": marker_executed_in_browser,
    "marker_reaches_dom_sink": marker_reaches_dom_sink,
    "marker_persisted_unescaped": marker_persisted_unescaped,
}

# Proof that comes from the browser probe (script execution, a DOM sink, stored markup), not from a
# response pair. `marker_executed_in_browser` is the only one of these that confirms a finding.
BROWSER_SIGNALS: frozenset[str] = frozenset(
    {"marker_executed_in_browser", "marker_reaches_dom_sink", "marker_persisted_unescaped"}
)

# Signals produced by passive analysis (EPIC-08) rather than by comparing two responses. They
# are valid proving signals for a check but have no entry in `DETECTORS`.
PASSIVE_SIGNALS: frozenset[str] = frozenset(
    {
        "header_absent",
        "header_misconfigured",
        "cookie_flag_missing",
        "cors_permissive",
        "technology_disclosed",
        "verbose_error_exposed",
        "sensitive_data_exposed",
        "undocumented_endpoint",
        "schema_exposed",
    }
)


# Proof that arrives from outside the response pair: an out-of-band callback (EPIC-09, needs an
# OAST address). Named here so a check can depend on it; nothing in this module produces it.
OUT_OF_BAND_SIGNALS: frozenset[str] = frozenset({"oast_callback_received"})

# Emitted by a dedicated stage (preflight, discovery, authenticate), not by comparing
# two responses in the active loop and not by the passive header pass.
RECON_SIGNALS: frozenset[str] = frozenset(
    {
        "dangerous_method_accepted",
        "waf_detected",
        "hidden_path_exposed",
        "directory_listed",
        "session_fixed",
        "session_lifetime_excessive",
        "credential_reused",
        "graphql_introspection_enabled",
        "graphql_batch_accepted",
        "ambiguous_request_framing",
        "postmessage_origin_missing",
    }
)


def signal_names() -> frozenset[str]:
    """Every signal name a check may legitimately name as proof."""
    return frozenset(DETECTORS) | PASSIVE_SIGNALS | OUT_OF_BAND_SIGNALS | TLS_SIGNAL_NAMES | RECON_SIGNALS


def run_detectors(
    baseline: ResponseSnapshot,
    test: ResponseSnapshot,
    ctx: DetectionContext | None = None,
    names: Sequence[str] | None = None,
) -> list[DetectorSignal]:
    """Run the named detectors (default: all) in a fixed order. A detector that raises is
    treated as producing nothing: a bug in one pattern must not hide the others' signals
    or fail a scan."""
    context = ctx or _EMPTY
    wanted = [n for n in DETECTORS if names is None or n in names]
    signals: list[DetectorSignal] = []
    for name in wanted:
        try:
            signals.extend(DETECTORS[name](baseline, test, context))
        except Exception:  # noqa: BLE001
            continue
    return signals
