"""secret_mask.py — keep secret values out of prompts, stored findings and logs (LLM02).

Pure and stdlib-only, so the engine (which cannot import ``app``) and the app
(which loads this file by path) share one implementation.

A secret *value* is replaced by ``«REDACTED:len=N»``. Everything around it is
kept — the variable name, the quotes, the surrounding code — and so is the
**number of lines**: a prompt's line numbers, ``reanchor_line`` and the
occurrence identity must not move. The model can still see that a hardcoded
literal exists and judge it; it just never receives the value.

Three kinds of detector, all conservative (a missed secret is the cost of not
corrupting code the model must analyse):

* known key shapes (cloud/VCS/payment tokens, JWTs, bearer tokens, PEM private
  keys, ``scheme://user:password@host``);
* quoted literals assigned to a credential-named key
  (``password = "…"``, ``"api_key": "…"``);
* unquoted ``key=value`` / ``key: value`` configuration lines whose value is not
  a plain identifier (``spring.datasource.password=admin123``). A value that is
  only letters, ``_`` and ``.`` (``password: string``, ``password = getPw``) is
  left alone because in source code that is a type or an expression; the
  consequence is that a dictionary-word config password (``password=changeme``)
  is not masked by this rule.

Masking is idempotent and never raises.
"""

from __future__ import annotations

import re
from typing import Any, Callable, List, Tuple

MARK = "«REDACTED"
_BOUND = "{0,60}"  # bounded so a long identifier-like run cannot go quadratic


def placeholder(value: str) -> str:
    return f"{MARK}:len={len(value)}»"


_CRED_NAMES = (
    r"(?:pass(?:word|wd|phrase)?|pwd|secret|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|token|credentials?)"
)
_KEY = rf"[\w.\-]{_BOUND}{_CRED_NAMES}[\w.\-]{_BOUND}"

# A key whose last word says the value *describes* a credential rather than being one.
_NON_SECRET_SUFFIXES = (
    "header", "name", "param", "field", "url", "uri", "path", "type", "prefix", "suffix",
    "endpoint", "claim", "attribute", "label", "message", "msg", "regex", "pattern",
    "format", "scheme", "expires", "expiry", "ttl", "length", "size", "min", "max",
    "count", "file", "dir", "id",
)

_PEM = re.compile(
    r"(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)(.*?)(-----END [A-Z0-9 ]*PRIVATE KEY-----)",
    re.DOTALL,
)
_PEM_LINE = re.compile(r"^(\s*\d+:\s?)?(.*)$")

_SHAPES = [
    re.compile(p) for p in (
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        r"\bgh[pousr]_[A-Za-z0-9]{30,}\b",
        r"\bgithub_pat_[A-Za-z0-9_]{40,}\b",
        r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b",
        r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b",
        r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b",
        r"\bsk-[A-Za-z0-9]{32,}\b",
        r"\bAIza[0-9A-Za-z_\-]{35}\b",
        r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b",
    )
]
_BEARER = re.compile(r"(\bBearer\s+)([A-Za-z0-9._~+/=\-]{20,})", re.IGNORECASE)
_URL_CRED = re.compile(
    r"(?<![a-z0-9+.\-])([a-z][a-z0-9+.\-]{0,30}://[^\s:/@\"']{1,100}:)([^\s@/\"']{1,200})(?=@)",
    re.IGNORECASE,
)
_QUOTED = re.compile(
    rf"(?<![\w.\-])(?P<key>{_KEY})[\"']?\s*(?::=|=>|[:=])\s*(?P<q>[\"'])(?P<val>[^\"'\n\r]{{4,}}?)(?P=q)",
    re.IGNORECASE,
)
_UNQUOTED = re.compile(
    rf"(?<![\w.\-\"'])(?P<key>{_KEY})(?P<sep>[ \t]*[:=][ \t]*)(?P<val>[^\s\"'#;(){{}}\[\],<>$]{{4,}})"
    r"(?=[ \t]*(?:#.*)?$)",
    re.IGNORECASE | re.MULTILINE,
)
_IDENTIFIER_LIKE = re.compile(r"^[A-Za-z_][A-Za-z_.]*$")
_TEMPLATED = ("${", "#{", "{{", "<", "%(", "$(", MARK)


def _is_templated(value: str) -> bool:
    return value.startswith(_TEMPLATED) or set(value) <= {"*", "x", "X", "-", "."}


def _describes_a_credential(key: str) -> bool:
    flat = re.sub(r"[^a-z0-9]", "", key.lower())
    return any(flat.endswith(suffix) for suffix in _NON_SECRET_SUFFIXES)


def _mask_pem(text: str, count: List[int]) -> str:
    def repl(match: "re.Match[str]") -> str:
        lines = []
        for line in match.group(2).split("\n"):
            prefix, rest = _PEM_LINE.match(line).groups()  # type: ignore[union-attr]
            if rest.strip():
                count[0] += 1
                lines.append(f"{prefix or ''}{MARK}:private-key-line»")
            else:
                lines.append(line)
        return match.group(1) + "\n".join(lines) + match.group(3)

    return _PEM.sub(repl, text)


def _sub(pattern: "re.Pattern[str]", text: str, count: List[int], build: Callable[["re.Match[str]"], str]) -> str:
    def repl(match: "re.Match[str]") -> str:
        out = build(match)
        if out != match.group(0):
            count[0] += 1
        return out

    return pattern.sub(repl, text)


def mask_text(text: str) -> Tuple[str, int]:
    """(`text` with secret values replaced, how many were)."""
    if not text or not isinstance(text, str):
        return text, 0
    try:
        count = [0]
        out = _mask_pem(text, count) if "PRIVATE KEY" in text else text
        for shape in _SHAPES:
            out = _sub(shape, out, count, lambda m: placeholder(m.group(0)))
        out = _sub(_BEARER, out, count, lambda m: m.group(1) + placeholder(m.group(2)))
        out = _sub(
            _URL_CRED, out, count,
            lambda m: m.group(0) if _is_templated(m.group(2)) else m.group(1) + placeholder(m.group(2)),
        )

        def quoted(m: "re.Match[str]") -> str:
            val = m.group("val")
            if _is_templated(val) or re.search(r"\s", val) or _describes_a_credential(m.group("key")):
                return m.group(0)
            start, end = m.span("val")
            return m.group(0)[: start - m.start()] + placeholder(val) + m.group(0)[end - m.start():]

        out = _sub(_QUOTED, out, count, quoted)

        def unquoted(m: "re.Match[str]") -> str:
            val = m.group("val")
            if _is_templated(val) or _IDENTIFIER_LIKE.match(val) or _describes_a_credential(m.group("key")):
                return m.group(0)
            return m.group("key") + m.group("sep") + placeholder(val)

        out = _sub(_UNQUOTED, out, count, unquoted)
        return out, count[0]
    except Exception:  # noqa: BLE001 — masking must never break a scan
        return text, 0


def mask(text: str) -> str:
    return mask_text(text)[0]


def mask_value(value: Any) -> Any:
    """`mask` applied to every string inside a dict/list/tuple (new objects; the
    input is never modified). Keys are left as they are."""
    if isinstance(value, str):
        return mask_text(value)[0]
    if isinstance(value, dict):
        return {k: mask_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [mask_value(v) for v in value]
    return value
