"""Non-destructive test-input validation (DAST-01-060).

Model-proposed test inputs are untrusted: each one is validated before anything is
sent and rejected if it could change or destroy target state.

`validate_test_input` is pure. It layers three checks, because neither a deny-list
nor an allow-shape is sufficient alone:

1. **method gate** - a state-changing method is rejected while safe mode is on;
2. **shape gate** - bounded length, no NUL/control characters (what a probe looks
   like, independent of what it says);
3. **deny-list** - a versioned, data-driven list of regexes (see
   `app/dast/data/input_rules.json`, loaded by `app.dast.input_rules`) run against
   the raw value *and* every decoded/normalized view of it, so casing, URL/HTML/
   unicode escapes, inline SQL comments, shell quoting tricks and base64 wrapping do
   not slip a destructive statement past a literal match.

Residual risk, by design: a validator reduces, it does not eliminate, destructive
output. A sufficiently creative encoding, or an application-specific destructive
verb the rule list does not know, can pass. Safe mode, scope and the disposable-
target requirement in `policy.py` are the real backstops; this is defence in depth.
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import unquote, unquote_plus

from .policy import SAFE_METHODS, STATE_CHANGING_METHODS

METHOD_GATE_RULE = "method-gate"
SHAPE_RULE = "shape-gate"

RULE_LIST_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    reason: str = ""
    rule_id: str = ""  # the rule that rejected the input; empty when accepted


InputValidator = Callable[[Mapping[str, Any]], ValidationResult]


@dataclass(frozen=True)
class ProposedTest:
    """A constructed test as the active-testing loop proposes it."""

    method: str
    location: str  # a `Location` value: query | path | header | body | ...
    value: str


@dataclass(frozen=True)
class InputRule:
    rule_id: str
    reason: str
    pattern: re.Pattern[str]
    safe_mode_only: bool = False  # only enforced while safe mode is on


@dataclass(frozen=True)
class ShapeLimits:
    max_length: int = 2000
    allow_control_chars: str = "\t\r\n"  # control characters that are still acceptable


@dataclass(frozen=True)
class RuleList:
    version: int
    rules: tuple[InputRule, ...]
    shape: ShapeLimits = field(default_factory=ShapeLimits)


_FLAGS = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}


def parse_rule_list(data: Mapping[str, Any]) -> RuleList:
    """Build a `RuleList` from its JSON form. Raises ValueError on a malformed list so a
    bad edit fails loudly at load time instead of silently disabling a rule."""
    if data.get("schema_version") != RULE_LIST_SCHEMA_VERSION:
        raise ValueError(f"unsupported rule-list schema_version: {data.get('schema_version')!r}")
    seen: set[str] = set()
    rules: list[InputRule] = []
    for raw in data.get("deny", ()):
        rule_id = raw.get("id")
        if not rule_id or not raw.get("reason") or not raw.get("pattern"):
            raise ValueError(f"deny rule needs id, reason and pattern: {raw!r}")
        if rule_id in seen:
            raise ValueError(f"duplicate deny rule id: {rule_id}")
        seen.add(rule_id)
        flags = 0
        for ch in raw.get("flags", "i"):
            if ch not in _FLAGS:
                raise ValueError(f"rule {rule_id}: unknown regex flag {ch!r}")
            flags |= _FLAGS[ch]
        try:
            pattern = re.compile(raw["pattern"], flags)
        except re.error as exc:
            raise ValueError(f"rule {rule_id}: invalid pattern: {exc}") from exc
        rules.append(InputRule(rule_id, raw["reason"], pattern, bool(raw.get("safe_mode_only", False))))
    shape_raw = data.get("shape") or {}
    shape = ShapeLimits(
        max_length=int(shape_raw.get("max_length", ShapeLimits.max_length)),
        allow_control_chars=str(shape_raw.get("allow_control_chars", ShapeLimits.allow_control_chars)),
    )
    if shape.max_length < 1:
        raise ValueError("shape.max_length must be >= 1")
    return RuleList(version=int(data.get("version", 1)), rules=tuple(rules), shape=shape)


# ---- decoded views --------------------------------------------------------------------------

_MAX_VIEWS = 48
_MAX_VIEW_CHARS = 20_000
_UNICODE_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})|%u([0-9a-fA-F]{4})")
_BASE64 = re.compile(r"^[A-Za-z0-9+/_-]{16,}={0,2}$")
_BLOCK_COMMENT = re.compile(r"/\*(?!\!).*?\*/", re.DOTALL)
_MYSQL_CONDITIONAL = re.compile(r"/\*!\d*|\*/")
_LINE_COMMENT = re.compile(r"(?:--|#)[^\n\r]*(?:[\n\r]+|$)")  # DROP --\nTABLE x: a comment ends at the line break and the tokens still join
_SHELL_QUOTE_TRICKS = re.compile(r"""(?:\$\{?IFS\}?(?:\$\d)?)|['"`\\]""")
_WHITESPACE = re.compile(r"\s+")


def _unescape_unicode(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        return chr(int(next(g for g in match.groups() if g), 16))

    return _UNICODE_ESCAPE.sub(repl, text)


def _decode_chain(value: str, decoder: Callable[[str], str], rounds: int = 4) -> list[str]:
    out: list[str] = []
    current = value
    for _ in range(rounds):
        decoded = decoder(current)
        if decoded == current:
            break
        out.append(decoded)
        current = decoded
    return out


def _try_base64(value: str) -> str | None:
    candidate = value.strip()
    if not _BASE64.match(candidate):
        return None
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        raw = base64.b64decode(padded.replace("-", "+").replace("_", "/"), validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    return text if text and text.isprintable() else None


def _normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    # Drop zero-width / formatting characters and NULs used to split keywords.
    text = "".join(ch for ch in text if ch != "\x00" and unicodedata.category(ch) != "Cf")
    return _WHITESPACE.sub(" ", text)


def decoded_views(value: str) -> list[str]:
    """The raw value plus every plausible decoded/normalized form of it, deduplicated."""
    stage_one: list[str] = [value]
    stage_one += _decode_chain(value, unquote)
    stage_one += _decode_chain(value, unquote_plus)
    for text in list(stage_one):
        unescaped = html.unescape(text)
        if unescaped != text:
            stage_one.append(unescaped)
        stage_one.append(_unescape_unicode(text))
        b64 = _try_base64(text)
        if b64 is not None:
            stage_one.append(b64)

    views: dict[str, None] = {}
    for text in stage_one:
        text = text[:_MAX_VIEW_CHARS]
        normalized = _normalize(text)
        variants = (
            text,
            normalized,
            _BLOCK_COMMENT.sub(" ", normalized),  # DROP/**/TABLE
            _BLOCK_COMMENT.sub("", normalized),  # DR/**/OP
            _MYSQL_CONDITIONAL.sub(" ", normalized),  # /*!50000DROP*/ TABLE
            _normalize(_LINE_COMMENT.sub(" ", text)),  # DROP --<newline>TABLE, DROP #<newline>TABLE
            _normalize(_LINE_COMMENT.sub(" ", _BLOCK_COMMENT.sub(" ", text))),
            _normalize(_SHELL_QUOTE_TRICKS.sub(lambda m: " " if m.group(0).startswith("$") else "", normalized)),
        )
        for variant in variants:
            views.setdefault(variant)
            if len(views) >= _MAX_VIEWS:
                return list(views)
    return list(views)


# ---- the validator --------------------------------------------------------------------------


def _shape_problem(value: str, shape: ShapeLimits) -> str | None:
    if len(value) > shape.max_length:
        return f"input is {len(value)} characters, over the {shape.max_length} limit"
    for ch in value:
        if ch == "\x00":
            return "input contains a NUL byte"
        if (ord(ch) < 0x20 or ord(ch) == 0x7F) and ch not in shape.allow_control_chars:
            return "input contains a control character"
    return None


FOREIGN_HOST_RULE = "foreign-host"
# `scheme://host` anywhere, or a protocol-relative `//host` that starts a token (so `..//..//etc` is not one).
_URL_HOST = re.compile(
    r"(?:(?<![\w])[a-z][a-z0-9+.-]*:)?(?:(?<=^)|(?<=[\s'\"=(\[,{;|&])|(?<=:))//(?:[^\s/@'\"<>]*@)?(\[[0-9a-f:.]+\]|[^\s/:?#'\"<>)\]]+)",
    re.IGNORECASE,
)


def foreign_hosts(views: Sequence[str], allowed: frozenset[str]) -> list[str]:
    """Hosts named by URLs inside the input (in any decoded view) that are not in `allowed`."""
    found: list[str] = []
    for view in views:
        for match in _URL_HOST.finditer(view):
            host = match.group(1).strip("[]").rstrip(".").lower()
            if host and "." in host or ":" in host or host == "localhost":
                if host not in allowed and host not in found:
                    found.append(host)
    return found


def validate_test_input(
    test: ProposedTest,
    rules: RuleList,
    *,
    safe_mode: bool = True,
    allow_state_changing: bool = False,
    allowed_hosts: frozenset[str] | None = None,
) -> ValidationResult:
    """Accept or reject one constructed test. Never raises on hostile input."""
    method = (test.method or "").strip().upper()
    if method not in SAFE_METHODS:
        if method not in STATE_CHANGING_METHODS:
            return ValidationResult(False, f"method {method or '<empty>'!r} is not supported", METHOD_GATE_RULE)
        if safe_mode and not allow_state_changing:
            return ValidationResult(False, f"{method} is state-changing and safe mode is on", METHOD_GATE_RULE)

    value = test.value if isinstance(test.value, str) else str(test.value)
    problem = _shape_problem(value, rules.shape)
    if problem:
        return ValidationResult(False, problem, SHAPE_RULE)

    views = decoded_views(value)
    for rule in rules.rules:
        if rule.safe_mode_only and not safe_mode:
            continue
        if any(rule.pattern.search(view) for view in views):
            return ValidationResult(False, rule.reason, rule.rule_id)
    if allowed_hosts is not None:
        others = foreign_hosts(views, allowed_hosts)
        if others:
            return ValidationResult(
                False,
                f"the input names another host ({others[0]!r}); a test may only name the target or the configured out-of-band address",
                FOREIGN_HOST_RULE,
            )
    return ValidationResult(True)


def validate_marker_value(
    value: str,
    rules: RuleList,
    *,
    allowed_hosts: frozenset[str] | None = None,
) -> ValidationResult:
    """Shape and deny-list only, for an inert browser marker. The submit method is decided by the
    policy's marker-submit exception, not by this gate, so a marker is not rejected for being
    carried in a POST."""
    value = value if isinstance(value, str) else str(value)
    problem = _shape_problem(value, rules.shape)
    if problem:
        return ValidationResult(False, problem, SHAPE_RULE)
    views = decoded_views(value)
    for rule in rules.rules:
        if any(rule.pattern.search(view) for view in views):
            return ValidationResult(False, rule.reason, rule.rule_id)
    if allowed_hosts is not None:
        others = foreign_hosts(views, allowed_hosts)
        if others:
            return ValidationResult(
                False,
                f"the input names another host ({others[0]!r}); a test may only name the target or the configured out-of-band address",
                FOREIGN_HOST_RULE,
            )
    return ValidationResult(True)


def reject_reasons(rules: RuleList) -> Sequence[str]:
    """Every rule id this list can reject with (for docs and coverage tests)."""
    return (METHOD_GATE_RULE, SHAPE_RULE, *(rule.rule_id for rule in rules.rules))


# ---- the validated-test type ----------------------------------------------------------------
#
# The active-testing loop sends only `ValidatedTest`s. The constructor refuses to run unless the
# module-private mint token is supplied, and the token is used in exactly one place: here, after the
# validator accepted the proposal. Nothing else in the engine can fabricate one, so "an input that
# did not pass the validator is never sent" holds by construction (the sender also type-checks).

PARAMETER_RULE = "parameter-gate"
RESTRICTED_HEADERS = frozenset(
    {
        "host", "content-length", "transfer-encoding", "connection", "cookie", "authorization", "proxy-authorization", "upgrade", "te", "expect",
        # Method-override headers turn a harmless GET into a DELETE on frameworks that honour them, past the method gate.
        "x-http-method-override", "x-method-override", "x-http-method", "x-http-method-name",
    }
)
# The same trick as a query or body parameter (Rails, Laravel, Symfony and others read `_method`).
METHOD_OVERRIDE_PARAMETERS = frozenset({"_method", "__method", "_http_method", "x-http-method-override", "x-http-method", "x-method-override"})
_VERB_PARAMETERS = frozenset({"method", "verb", "http_method", "httpmethod", "request_method"})
_VERBS = frozenset({"POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT"})
_HEADER_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,59}$")
MAX_PARAMETER_CHARS = 100
_MINT = object()


@dataclass(frozen=True)
class ValidatedTest:
    check_id: str
    parameter: str
    location: str
    method: str
    value: str
    expected_signal: str = ""
    control_value: str = ""  # a logically-false variant (boolean checks); validated like `value`, or empty
    _mint: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._mint is not _MINT:
            raise TypeError("a ValidatedTest can only be produced by validate_proposal()")


def _parameter_problem(location: str, parameter: str, value: str) -> str | None:
    if not parameter or len(parameter) > MAX_PARAMETER_CHARS or any(ord(c) < 0x20 or ord(c) == 0x7F for c in parameter):
        return "the parameter name is empty, too long or contains control characters"
    lowered = parameter.strip().lower()
    if lowered in METHOD_OVERRIDE_PARAMETERS or (lowered in _VERB_PARAMETERS and value.strip().upper() in _VERBS):
        return "a test may not carry a method override, which would get around the method gate"
    if location == "header":
        if not _HEADER_TOKEN.match(parameter) or parameter.lower() in RESTRICTED_HEADERS:
            return f"header {parameter[:40]!r} may not be set by a test"
        if any(c in value for c in "\r\n\x00"):
            return "a header value may not contain line breaks"
    return None


def validate_proposal(
    *,
    check_id: str,
    parameter: str,
    location: str,
    method: str,
    value: str,
    rules: RuleList,
    expected_signal: str = "",
    control_value: str = "",
    safe_mode: bool = True,
    allow_state_changing: bool = False,
    allowed_hosts: frozenset[str] | None = None,
) -> tuple[ValidationResult, ValidatedTest | None]:
    """Validate one proposed test. On acceptance returns the `ValidatedTest` (the only way to get
    one); a rejected proposal yields `(result, None)`. A control value that fails validation is
    dropped on its own: the test still runs, without the boolean-divergence control."""
    location = (location or "").strip().lower()
    value = value if isinstance(value, str) else str(value)
    problem = _parameter_problem(location, parameter, value)
    if problem:
        return ValidationResult(False, problem, PARAMETER_RULE), None
    result = validate_test_input(
        ProposedTest(method, location, value), rules, safe_mode=safe_mode, allow_state_changing=allow_state_changing, allowed_hosts=allowed_hosts
    )
    if not result.ok:
        return result, None
    control = ""
    if control_value:
        control_text = control_value if isinstance(control_value, str) else str(control_value)
        control_ok = validate_test_input(
            ProposedTest(method, location, control_text), rules, safe_mode=safe_mode, allow_state_changing=allow_state_changing, allowed_hosts=allowed_hosts
        )
        if control_ok.ok and _parameter_problem(location, parameter, control_text) is None:
            control = control_text
    return result, ValidatedTest(
        check_id, parameter, location, (method or "").strip().upper(), value, expected_signal, control, _mint=_MINT
    )
