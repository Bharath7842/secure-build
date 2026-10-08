"""Passive analysis (DAST-08-010 .. -030): pure checks over responses the scan already saw.

Nothing here sends a request or asks a model. The inputs are `RecordedExchange`s (the browser
recorder's output, plus the preflight's root response), and every check is a function
`exchange -> [PassiveHit]`. A hit names the check it belongs to, the header/cookie/pattern it is
about (`param`), the detector signal that proves it, and the redacted evidence.

Dedupe is part of the contract: a missing header is one issue however many responses lack it, so
`dedupe_hits` collapses hits on `(check_id, param)` and keeps the first response as the
representative and the others as affected targets.

Precision limits (documented, tested): pattern families marked `ambiguous` (personal-data shapes,
JWT-looking strings, private addresses) are recorded `false_positive` (the match is not a
confirmed issue); the reflected-origin CORS check needs two distinct request origins echoed back
before it is a confirmed hit; the `Secure` cookie flag is only judged on HTTPS responses.
"""

from __future__ import annotations

import json
import re
from base64 import urlsafe_b64decode
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit

from . import detector_patterns as P
from .detectors import db_error_surfaced, stack_trace_leaked
from .entities import ResponseSnapshot
from .traffic import RecordedExchange

# Check ids (all are entries in the check catalog).
CSP, HSTS, XCTO, CLICKJACKING, REFERRER = (
    "dast-passive-missing-csp",
    "dast-passive-missing-hsts",
    "dast-passive-missing-xcto",
    "dast-passive-clickjacking",
    "dast-passive-missing-referrer-policy",
)
COOKIES, CORS, TECH, VERBOSE, SENSITIVE = (
    "dast-passive-cookie-flags",
    "dast-passive-cors-permissive",
    "dast-passive-tech-disclosure",
    "dast-passive-verbose-errors",
    "dast-passive-sensitive-data",
)
PASSIVE_CHECK_IDS = (CSP, HSTS, XCTO, CLICKJACKING, REFERRER, COOKIES, CORS, TECH, VERBOSE, SENSITIVE)

TRUE_POSITIVE, UNVERIFIED, FALSE_POSITIVE = "true_positive", "unverified", "false_positive"
HSTS_MIN_MAX_AGE = 15_552_000  # 180 days
MAX_EXCERPT = 240
MAX_AFFECTED = 25


@dataclass(frozen=True)
class PassiveHit:
    check_id: str
    param: str  # the header, cookie or pattern family the finding is about
    signal: str  # detector signal name (header_absent, cookie_flag_missing, ...)
    detail: str  # short, redacted, human-readable
    method: str
    url: str
    status: int | None
    excerpt: str = ""  # evidence; never holds a sensitive match
    verdict: str = TRUE_POSITIVE
    severity_shift: int = 0  # +1 raises the check's severity one step, -1 lowers it
    note: str = ""  # why a hit is not confirmed, or a severity rationale


@dataclass(frozen=True)
class DedupedHit:
    hit: PassiveHit  # the representative (first response it was observed on)
    affected: tuple[str, ...]  # "METHOD path" of every response it was observed on, first included
    occurrences: int


# ---- pattern data -----------------------------------------------------------------------------


@dataclass(frozen=True)
class PatternFamily:
    family_id: str
    check: str  # "verbose" | "sensitive"
    label: str
    pattern: re.Pattern[str]
    confidence: str = "definite"  # definite | ambiguous
    validator: str = ""  # "" | "luhn" | "jwt"
    errors_only: bool = False  # meaningful only in an error response (status >= 400)
    redact_match: bool = False  # the evidence never quotes the match itself


@dataclass(frozen=True)
class PatternSet:
    families: tuple[PatternFamily, ...] = ()
    disclosure_headers: tuple[str, ...] = ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator")
    versioned_headers: tuple[str, ...] = ("server",)
    version_re: re.Pattern[str] = re.compile(r"\d+\.\d+")
    meta_generator: re.Pattern[str] = re.compile(
        r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']{1,120})[\"']", re.IGNORECASE
    )


def parse_pattern_set(data: Mapping[str, Any]) -> PatternSet:
    """Build a `PatternSet` from the JSON data file. Raises ValueError on a malformed entry so a
    bad edit fails at load time rather than silently disabling a family."""
    if data.get("schema_version") != 1:
        raise ValueError(f"unsupported passive pattern schema_version: {data.get('schema_version')!r}")
    seen: set[str] = set()
    families: list[PatternFamily] = []
    for raw in data.get("families", ()):
        fid = str(raw.get("id") or "")
        if not fid or fid in seen:
            raise ValueError(f"passive pattern family needs a unique id: {raw!r}")
        seen.add(fid)
        if raw.get("check") not in ("verbose", "sensitive"):
            raise ValueError(f"family {fid}: check must be 'verbose' or 'sensitive'")
        if raw.get("confidence", "definite") not in ("definite", "ambiguous"):
            raise ValueError(f"family {fid}: confidence must be 'definite' or 'ambiguous'")
        if raw.get("validator", "") not in ("", "luhn", "jwt"):
            raise ValueError(f"family {fid}: unknown validator {raw.get('validator')!r}")
        try:
            pattern = re.compile(str(raw.get("pattern") or ""), re.MULTILINE | (re.IGNORECASE if "i" in raw.get("flags", "") else 0))
        except re.error as exc:
            raise ValueError(f"family {fid}: invalid pattern: {exc}") from exc
        families.append(
            PatternFamily(
                fid, raw["check"], str(raw.get("label") or fid), pattern, raw.get("confidence", "definite"),
                raw.get("validator", ""), bool(raw.get("errors_only", False)), bool(raw.get("redact_match", raw["check"] == "sensitive")),
            )
        )
    disclosure = data.get("disclosure") or {}
    base = PatternSet()
    return PatternSet(
        tuple(families),
        tuple(str(h).lower() for h in disclosure.get("headers", base.disclosure_headers)),
        tuple(str(h).lower() for h in disclosure.get("versioned_headers", base.versioned_headers)),
        re.compile(str(disclosure.get("version_pattern") or base.version_re.pattern)),
    )


# ---- small helpers ----------------------------------------------------------------------------


def _header(headers: Mapping[str, str] | None, name: str) -> str | None:
    for key, value in (headers or {}).items():
        if str(key).lower() == name:
            return str(value)
    return None


def _label(ex: RecordedExchange) -> str:
    return f"{ex.method.upper()} {urlsplit(ex.url).path or '/'}"


def _is_html(ex: RecordedExchange) -> bool:
    return "html" in (ex.content_type or "").lower()


def _ok(ex: RecordedExchange) -> bool:
    return ex.status is not None and 200 <= ex.status < 300


def _hit(ex: RecordedExchange, check_id: str, param: str, signal: str, detail: str, excerpt: str = "", **kw: Any) -> PassiveHit:
    return PassiveHit(check_id, param, signal, detail, ex.method.upper(), ex.url, ex.status, excerpt[:MAX_EXCERPT], **kw)


def _headers_summary(ex: RecordedExchange, names: Iterable[str]) -> str:
    present = [f"{n}: {_header(ex.response_headers, n)}" for n in names if _header(ex.response_headers, n) is not None]
    return f"HTTP {ex.status} {urlsplit(ex.url).path or '/'}; " + ("; ".join(present) if present else "none of the related headers were sent")


# ---- security headers (DAST-08-010) -----------------------------------------------------------

_WEAK_CSP_TOKENS = ("'unsafe-inline'", "'unsafe-eval'")


def _csp_directives(policy: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in policy.split(";"):
        tokens = part.split()
        if tokens:
            out.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return out


def _csp_weakness(policy: str) -> str:
    directives = _csp_directives(policy)
    sources = directives.get("script-src") or directives.get("default-src")
    if sources is None:
        return "no script-src or default-src directive, so scripts are not restricted"
    for token in _WEAK_CSP_TOKENS:
        if token in sources:
            return f"script sources allow {token}"
    if "*" in sources or "data:" in sources or "http:" in sources:
        return "script sources allow any origin"
    return ""


def check_security_headers(ex: RecordedExchange) -> list[PassiveHit]:
    if ex.asset or not _ok(ex):
        return []
    hits: list[PassiveHit] = []
    h = ex.response_headers
    csp = _header(h, "content-security-policy")
    xfo = _header(h, "x-frame-options")
    html = _is_html(ex)
    if html:
        if csp is None:
            note = " (a report-only policy is present but is not enforced)" if _header(h, "content-security-policy-report-only") else ""
            hits.append(_hit(ex, CSP, "Content-Security-Policy", "header_absent", f"no Content-Security-Policy header{note}", _headers_summary(ex, ["content-security-policy"])))
        else:
            weakness = _csp_weakness(csp)
            if weakness:
                hits.append(_hit(ex, CSP, "Content-Security-Policy", "header_misconfigured", weakness, f"Content-Security-Policy: {csp[:160]}"))
        frame_ancestors = bool(csp and "frame-ancestors" in _csp_directives(csp))
        if xfo is None and not frame_ancestors:
            hits.append(_hit(ex, CLICKJACKING, "X-Frame-Options", "header_absent", "neither X-Frame-Options nor CSP frame-ancestors restricts framing", _headers_summary(ex, ["x-frame-options", "content-security-policy"])))
        elif xfo is not None and xfo.strip().upper() not in ("DENY", "SAMEORIGIN") and not frame_ancestors:
            hits.append(_hit(ex, CLICKJACKING, "X-Frame-Options", "header_misconfigured", f"X-Frame-Options has the unsupported value {xfo.strip()[:40]!r}", f"X-Frame-Options: {xfo[:60]}"))
        referrer = _header(h, "referrer-policy")
        if referrer is None:
            hits.append(_hit(ex, REFERRER, "Referrer-Policy", "header_absent", "no Referrer-Policy header", _headers_summary(ex, ["referrer-policy"])))
        elif referrer.strip().lower() == "unsafe-url":
            hits.append(_hit(ex, REFERRER, "Referrer-Policy", "header_misconfigured", "Referrer-Policy: unsafe-url sends full URLs to every site", f"Referrer-Policy: {referrer}"))
    xcto = _header(h, "x-content-type-options")
    if xcto is None:
        hits.append(_hit(ex, XCTO, "X-Content-Type-Options", "header_absent", "no X-Content-Type-Options header", _headers_summary(ex, ["x-content-type-options"])))
    elif xcto.strip().lower() != "nosniff":
        hits.append(_hit(ex, XCTO, "X-Content-Type-Options", "header_misconfigured", f"X-Content-Type-Options is {xcto.strip()[:40]!r}, not nosniff", f"X-Content-Type-Options: {xcto[:60]}"))
    if urlsplit(ex.url).scheme == "https":
        hsts = _header(h, "strict-transport-security")
        if hsts is None:
            hits.append(_hit(ex, HSTS, "Strict-Transport-Security", "header_absent", "an HTTPS response carries no Strict-Transport-Security header", _headers_summary(ex, ["strict-transport-security"])))
        else:
            match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
            age = int(match.group(1)) if match else 0
            if age < HSTS_MIN_MAX_AGE:
                hits.append(_hit(ex, HSTS, "Strict-Transport-Security", "header_misconfigured", f"max-age {age}s is shorter than {HSTS_MIN_MAX_AGE}s", f"Strict-Transport-Security: {hsts[:100]}"))
    return hits


# ---- cookies (DAST-08-010) --------------------------------------------------------------------


def parse_set_cookie(value: str) -> list[tuple[str, dict[str, str]]]:
    """`(name, {attribute-lowercase: value})` for every cookie in a (newline-joined) header."""
    out: list[tuple[str, dict[str, str]]] = []
    for line in str(value).splitlines():
        head, *attrs = line.split(";")
        name = head.split("=", 1)[0].strip()
        if not name:
            continue
        parsed = {}
        for attr in attrs:
            key, _, val = attr.partition("=")
            if key.strip():
                parsed[key.strip().lower()] = val.strip()
        out.append((name, parsed))
    return out


def check_cookies(ex: RecordedExchange) -> list[PassiveHit]:
    raw = _header(ex.response_headers, "set-cookie")
    if raw is None or ex.asset:
        return []
    https = urlsplit(ex.url).scheme == "https"
    hits = []
    for name, attrs in parse_set_cookie(raw):
        missing = [flag for flag, key in (("HttpOnly", "httponly"), ("SameSite", "samesite")) if key not in attrs]
        if https and "secure" not in attrs:
            missing.append("Secure")
        if missing:
            shown = f"{name}=[REDACTED]" + "".join(f"; {k}" + (f"={v}" if v else "") for k, v in attrs.items())
            hits.append(_hit(ex, COOKIES, name, "cookie_flag_missing", f"cookie {name!r} lacks {', '.join(missing)}", f"Set-Cookie: {shown}"[:MAX_EXCERPT]))
    return hits


# ---- CORS (DAST-08-020) -----------------------------------------------------------------------


@dataclass(frozen=True)
class CorsAssessment:
    assessable: bool  # False when no request carried an Origin header (reflection cannot be judged)
    note: str = ""


def cors_assessment(traffic: Iterable[RecordedExchange]) -> CorsAssessment:
    if any(_header(ex.request_headers, "origin") is not None for ex in traffic if not ex.asset):
        return CorsAssessment(True)
    return CorsAssessment(False, "not assessable: no request carried an Origin header, so reflected-origin behaviour cannot be judged without sending probes")


def _origin_host(origin: str) -> str:
    return (urlsplit(origin).netloc or origin).lower()


def check_cors(traffic: Sequence[RecordedExchange]) -> list[PassiveHit]:
    hits: list[PassiveHit] = []
    reflections: dict[tuple[str, str], dict[str, RecordedExchange]] = {}  # (host, path) -> origin -> exchange
    for ex in traffic:
        if ex.asset:
            continue
        acao = _header(ex.response_headers, "access-control-allow-origin")
        if acao is None:
            continue
        credentials = (_header(ex.response_headers, "access-control-allow-credentials") or "").strip().lower() == "true"
        evidence = f"Access-Control-Allow-Origin: {acao[:120]}" + ("; Access-Control-Allow-Credentials: true" if credentials else "")
        request_origin = _header(ex.request_headers, "origin")
        if acao.strip() == "*" and credentials:
            hits.append(_hit(ex, CORS, "Access-Control-Allow-Origin", "cors_permissive", "wildcard origin combined with credentials", evidence, severity_shift=1))
        elif acao.strip().lower() == "null":
            hits.append(_hit(ex, CORS, "Access-Control-Allow-Origin", "cors_permissive", "the null origin is allowed", evidence, severity_shift=1 if credentials else 0))
        elif request_origin and acao.strip() == request_origin.strip() and _origin_host(request_origin) != (urlsplit(ex.url).netloc or "").lower():
            key = (urlsplit(ex.url).netloc.lower(), urlsplit(ex.url).path)
            reflections.setdefault(key, {}).setdefault(request_origin.strip(), ex)
            if credentials:
                reflections[key].setdefault("\0credentials", ex)
    for (_host, _path), by_origin in reflections.items():
        origins = [o for o in by_origin if o != "\0credentials"]
        first = by_origin[origins[0]]
        credentials = "\0credentials" in by_origin
        evidence = f"Access-Control-Allow-Origin echoed {', '.join(o[:60] for o in origins[:3])}" + ("; Access-Control-Allow-Credentials: true" if credentials else "")
        if len(origins) >= 2:
            hits.append(_hit(ex=first, check_id=CORS, param="Access-Control-Allow-Origin", signal="cors_permissive", detail="the server reflects any request origin", excerpt=evidence, severity_shift=1 if credentials else 0))
        else:
            hits.append(
                _hit(
                    first, CORS, "Access-Control-Allow-Origin", "cors_permissive", "the allowed origin equals the request origin", evidence,
                    verdict=FALSE_POSITIVE, severity_shift=1 if credentials else 0,
                    note="only one request origin was observed; a single allowed origin and a reflected one look the same without probing",
                )
            )
    return hits


# ---- technology disclosure (DAST-08-020) -------------------------------------------------------


def check_disclosure(ex: RecordedExchange, patterns: PatternSet) -> list[PassiveHit]:
    if ex.asset:
        return []
    hits = []
    for name in patterns.disclosure_headers:
        value = _header(ex.response_headers, name)
        if value:
            hits.append(_hit(ex, TECH, name, "technology_disclosed", f"{name} reveals {value[:60]!r}", f"{name}: {value[:80]}"))
    for name in patterns.versioned_headers:
        value = _header(ex.response_headers, name)
        if value and patterns.version_re.search(value):
            hits.append(_hit(ex, TECH, name, "technology_disclosed", f"{name} reveals the software version {value[:60]!r}", f"{name}: {value[:80]}"))
    if _is_html(ex) and ex.response_body:
        meta = patterns.meta_generator.search(ex.response_body)
        if meta:
            hits.append(_hit(ex, TECH, "meta-generator", "technology_disclosed", f"the page names its generator {meta.group(1)!r}", f'<meta name="generator" content="{meta.group(1)[:80]}">'))
    return hits


# ---- verbose errors and sensitive data (DAST-08-030) ------------------------------------------


def luhn_valid(digits: str) -> bool:
    nums = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(nums) <= 19 or len(set(nums)) == 1:
        return False
    total = 0
    for index, digit in enumerate(reversed(nums)):
        if index % 2:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def jwt_valid(token: str) -> bool:
    """Three dot-separated base64url parts whose header decodes to a JSON object naming `alg`."""
    parts = token.split(".")
    if len(parts) != 3 or not all(parts[:2]):
        return False
    try:
        header = json.loads(urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
    except (ValueError, UnicodeDecodeError):
        return False
    return isinstance(header, dict) and "alg" in header


_VALIDATORS = {"luhn": luhn_valid, "jwt": jwt_valid}


def _empty_snapshot() -> ResponseSnapshot:
    return ResponseSnapshot(status=200, length=0, body_excerpt="")


def check_errors_and_data(ex: RecordedExchange, patterns: PatternSet, wanted: frozenset[str]) -> list[PassiveHit]:
    """Verbose-error and sensitive-data families over the response body. The two leakage detectors
    from the active library (`stack_trace_leaked`, `db_error_surfaced`) are reused so one signal
    definition serves the passive and the active stage."""
    body = ex.response_body or ""
    if ex.asset or not body:
        return []
    hits: list[PassiveHit] = []
    if VERBOSE in wanted:
        snapshot = ResponseSnapshot(ex.status, len(body), body, ex.response_headers or {})
        for label, detector in (("stack_trace", stack_trace_leaked), ("database_error", db_error_surfaced)):
            for signal in detector(_empty_snapshot(), snapshot):
                hits.append(_hit(ex, VERBOSE, label, "verbose_error_exposed", f"the response exposes a {label.replace('_', ' ')}", signal.detail))
    for family in patterns.families:
        wanted_check = VERBOSE if family.check == "verbose" else SENSITIVE
        if wanted_check not in wanted or (family.errors_only and not (ex.status or 0) >= 400):
            continue
        found = None
        for match in family.pattern.finditer(body):
            validator = _VALIDATORS.get(family.validator)
            if validator is None or validator(match.group(0)):
                found = match
                break
        if found is None:
            continue
        if family.redact_match:
            excerpt = f"{family.label} found in the response body at offset {found.start()} ({len(found.group(0))} characters; value not recorded)"
        else:
            excerpt = " ".join(found.group(0).split())[:160]
        ambiguous = family.confidence == "ambiguous"
        hits.append(
            _hit(
                ex, wanted_check, family.family_id, "verbose_error_exposed" if family.check == "verbose" else "sensitive_data_exposed",
                f"{family.label} in the response body", excerpt,
                verdict=FALSE_POSITIVE if ambiguous else TRUE_POSITIVE,
                note=f"{family.label} patterns can match harmless data; confirm by hand" if ambiguous else "",
            )
        )
    return hits


# ---- the whole pass ---------------------------------------------------------------------------

_HEADER_CHECKS = frozenset({CSP, HSTS, XCTO, CLICKJACKING, REFERRER})


def analyze_exchange(ex: RecordedExchange, wanted: frozenset[str], patterns: PatternSet) -> list[PassiveHit]:
    """Every per-response check whose check id is in `wanted` (the enabled checks)."""
    hits: list[PassiveHit] = []
    if wanted & _HEADER_CHECKS:
        hits += [h for h in check_security_headers(ex) if h.check_id in wanted]
    if COOKIES in wanted:
        hits += check_cookies(ex)
    if TECH in wanted:
        hits += check_disclosure(ex, patterns)
    if wanted & {VERBOSE, SENSITIVE}:
        hits += check_errors_and_data(ex, patterns, wanted)
    return hits


def analyze_traffic(traffic: Sequence[RecordedExchange], wanted: Iterable[str], patterns: PatternSet) -> tuple[list[PassiveHit], CorsAssessment]:
    """All hits for the recorded traffic (not yet deduped) and whether CORS reflection was assessable."""
    enabled = frozenset(wanted)
    hits: list[PassiveHit] = []
    for ex in traffic:
        hits += analyze_exchange(ex, enabled, patterns)
    cors = cors_assessment(traffic)
    if CORS in enabled:
        hits += check_cors(traffic)
    return hits, cors


_VERDICT_RANK = {TRUE_POSITIVE: 0, FALSE_POSITIVE: 1, UNVERIFIED: 2}


def dedupe_hits(hits: Iterable[PassiveHit]) -> list[DedupedHit]:
    """One entry per `(check_id, param)`. The representative is the first confirmed hit, else the
    first hit; `affected` lists the responses in the order they were seen (capped)."""
    groups: dict[tuple[str, str], list[PassiveHit]] = {}
    for hit in hits:
        groups.setdefault((hit.check_id, hit.param), []).append(hit)
    out: list[DedupedHit] = []
    for group in groups.values():
        representative = min(group, key=lambda h: _VERDICT_RANK.get(h.verdict, 2))  # min is stable: first of the best
        affected: list[str] = []
        for h in group:
            dest = h.url if str(h.url).startswith(("http://", "https://")) else (urlsplit(h.url).path or "/")
            label = f"{h.method} {dest}"
            if label not in affected:
                affected.append(label)
        out.append(DedupedHit(representative, tuple(affected[:MAX_AFFECTED]), len(group)))
    return out


_SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def shift_severity(severity: str, shift: int) -> str:
    """`severity` moved `shift` steps (clamped to LOW..HIGH so a passive finding is never INFO
    from a lowering or CRITICAL from a raise)."""
    index = _SEVERITIES.index(severity) if severity in _SEVERITIES else 2
    return _SEVERITIES[max(1, min(3, index + shift))] if shift else severity


# Referenced by tests: the leakage patterns are shared with the active detectors, not copied.
SHARED_LEAK_PATTERNS = {"stack_trace": P.STACK_TRACE_PATTERNS, "database_error": P.DB_ERROR_PATTERNS}
