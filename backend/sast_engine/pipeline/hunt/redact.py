"""Secret redaction for code text that leaves the process (LLM prompts).

Only the secret *value* is masked; the surrounding code stays intact, so
`password = "«redacted»"` still tells the model a credential is hardcoded
(which is all a hardcoded-secret verdict needs) without shipping the
credential itself to a provider. Patterns mirror the catalog's secret rules
(rules/common.json `secret-*`, java.json `java-secretkeyspec-string-literal`
and `java-config-default-credential`, web.json `secret-config-unquoted`) but
capture just the value.

Redaction is deterministic and line-local, so the validator can ground a
quoted (redacted) line by redacting the original line the same way and
comparing — see `redaction_aware_equal`.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import List, Pattern, Tuple

REDACTED = "«redacted»"

# Values that are lookups, not secrets: masking them would hide exactly the
# evidence that a credential is *not* hardcoded.
_PLACEHOLDER_RE = re.compile(r"^\s*(\$\{|%\{|\{\{|#\{|\$[A-Z_]|env\(|<)", re.IGNORECASE)

_SECRET_NAME = (
    r"(?:password|passwd|pwd|passphrase|secret|token|api[_-]?key|apikey|access[_-]?key"
    r"|private[_-]?key|client[_-]?secret|credentials?|auth[_-]?key)"
)

# (pattern, value group) — each value group is replaced, the rest is kept.
_VALUE_PATTERNS: List[Tuple[Pattern[str], int]] = [
    # name = "value" / name: 'value' / "name": "value" (code, JSON, YAML)
    (re.compile(
        rf"(?i)({_SECRET_NAME}\w*[\"']?\s*[:=]\s*[\"'])([^\"'\n]{{3,}})([\"'])"
    ), 2),
    # getProperty("db.password", "fallback-literal")
    (re.compile(
        rf"(?i)(\bget(?:String|Property)\s*\(\s*\"[^\"]*{_SECRET_NAME}[^\"]*\"\s*,\s*\")([^\"\n]+)(\")"
    ), 2),
    # new SecretKeySpec("literal".getBytes(...))
    (re.compile(r"(new\s+SecretKeySpec\s*\(\s*\")([^\"\n]{4,})(\")"), 2),
    # Unquoted .properties / .env / .yml values: db.password=hunter2
    (re.compile(
        rf"(?im)^(\s*(?![#;])[\w.\-]*{_SECRET_NAME}[\w.\-]*\s*[=:]\s*)([^\s'\";]{{4,}})(\s*)$"
    ), 2),
    # Authorization: Bearer <token>
    (re.compile(r"(?i)(\bBearer\s+)([A-Za-z0-9\-._~+/]{12,}=*)()"), 2),
]

# Whole-token secrets with a recognisable shape.
_TOKEN_PATTERNS: List[Pattern[str]] = [
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),  # JWT
    re.compile(r"\b(?:ghp|gho|ghs|github_pat|glpat|xox[abpr]|sk_live|sk-[A-Za-z]*)[_\-]?[A-Za-z0-9_\-]{16,}\b"),
]
_PEM_RE = re.compile(
    r"-----BEGIN ([A-Z ]*)PRIVATE KEY-----[\s\S]*?-----END \1PRIVATE KEY-----"
)

# Quoted literals long and random enough to be key material even without a
# telling variable name.
_QUOTED_LITERAL_RE = re.compile(r"([\"'])([A-Za-z0-9+/=_\-]{24,})\1")
HIGH_ENTROPY_MIN_BITS = 4.0


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def _looks_random(value: str) -> bool:
    # Mixed character classes rule out identifiers like
    # "com_example_service_impl_factory" that are long but not secret.
    classes = sum(
        bool(re.search(pattern, value))
        for pattern in (r"[a-z]", r"[A-Z]", r"[0-9]")
    )
    return classes >= 2 and shannon_entropy(value) >= HIGH_ENTROPY_MIN_BITS


def redact_text(text: str) -> Tuple[str, int]:
    """Return (redacted text, number of values masked)."""
    if not text:
        return text, 0
    count = 0

    def _mask_value(group: int):
        def _sub(match: "re.Match[str]") -> str:
            nonlocal count
            value = match.group(group)
            if _PLACEHOLDER_RE.match(value) or value == REDACTED:
                return match.group(0)
            count += 1
            start, end = match.span(group)
            offset = match.start()
            whole = match.group(0)
            return whole[: start - offset] + REDACTED + whole[end - offset:]
        return _sub

    def _mask_whole(match: "re.Match[str]") -> str:
        nonlocal count
        count += 1
        # Keep the line count: callers rely on line numbers staying true.
        return REDACTED + "\n" * match.group(0).count("\n")

    out = _PEM_RE.sub(_mask_whole, text)
    for pattern, group in _VALUE_PATTERNS:
        out = pattern.sub(_mask_value(group), out)
    for pattern in _TOKEN_PATTERNS:
        out = pattern.sub(_mask_whole, out)

    def _mask_random_literal(match: "re.Match[str]") -> str:
        nonlocal count
        if not _looks_random(match.group(2)):
            return match.group(0)
        count += 1
        return f"{match.group(1)}{REDACTED}{match.group(1)}"

    out = _QUOTED_LITERAL_RE.sub(_mask_random_literal, out)
    return out, count


def redact(text: str) -> str:
    return redact_text(text)[0]


def _normalize(line: str) -> str:
    return " ".join((line or "").split())


def redaction_aware_equal(quoted: str, original: str) -> bool:
    """True when a line the model quoted matches the original source line,
    allowing for the redaction the model was shown (and for whitespace)."""
    q = _normalize(quoted)
    if not q:
        return False
    return q == _normalize(original) or q == _normalize(redact(original))
