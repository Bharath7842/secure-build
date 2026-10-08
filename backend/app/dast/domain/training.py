"""Training-data capture, pure parts (DAST-16-050): what may be kept, how it is scrubbed, how a
dataset is balanced and versioned.

The detectors are a free labeling oracle (design doc, §8.3): every active test yields
`(target, input, detector signals, deterministic verdict)`, and the deterministic verdict is the gold
label. This module decides which of those records are worth keeping and strips everything that could
identify a target or carry a credential before anything is stored.

Kept: only records where the model's proposal and the detectors' verdict *agree* (a downgrade or an
override by the guardrail is a disagreement and is left out), balanced across fail, pass and
inconclusive. Never kept: an input the non-destructive validator rejected (such an input is never
sent, so no record exists; `scrub_example` re-checks anyway), and anything from a project that has not
opted in.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
from typing import Any, Iterable, Mapping, Sequence

from .redaction import redact_text

LABELS = ("fail", "pass", "inconclusive")
_VERDICT_TO_LABEL = {"FAIL": "fail", "PASS": "pass", "INCONCLUSIVE": "inconclusive"}
MAX_TEXT_CHARS = 600

_URL = re.compile(r"\b(?:https?|wss?|ftp)://[^\s'\"<>)\]]+", re.IGNORECASE)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{1,4}(?![\w:])", re.IGNORECASE)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_JWT = re.compile(r"\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{4,}\b")
_BEARER = re.compile(r"\b(?:bearer|basic|token)\s+[\w.~+/=-]{8,}", re.IGNORECASE)
_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE)
_LONG_HEX = re.compile(r"\b[0-9a-f]{16,}\b", re.IGNORECASE)
_LONG_TOKEN = re.compile(r"\b[A-Za-z0-9_-]{32,}\b")
_BIG_NUMBER = re.compile(r"\b\d{6,}\b")
_COOKIE = re.compile(r"(?i)\b(set-cookie|cookie)\s*:\s*[^\n]+")
_HOSTNAME = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|dev|app|local|internal|test|example|corp|lan|cloud|co|uk|de|fr)\b", re.IGNORECASE)


def scrub_text(text: str, *, hosts: Iterable[str] = (), secrets: Iterable[str] = ()) -> str:
    """`text` with target-identifying and credential-bearing content replaced by placeholders: known
    hosts and secrets first (exact), then URLs (host and any credentials), IP addresses, e-mail
    addresses, JWTs and bearer tokens, cookies, UUIDs, long hex or token-like strings and long numbers."""
    out = str(text)
    for secret in sorted((s for s in secrets if s), key=len, reverse=True):
        out = out.replace(secret, "<secret>")
    out = redact_text(out)
    for host in sorted((h for h in hosts if h), key=len, reverse=True):
        out = re.sub(re.escape(host), "<host>", out, flags=re.IGNORECASE)
    out = _COOKIE.sub(lambda m: f"{m.group(1)}: <redacted>", out)
    out = _URL.sub(lambda m: re.sub(r"^(\w+://)[^/\s?#]*", r"\1<host>", m.group(0)), out)
    for pattern, placeholder in ((_JWT, "<secret>"), (_BEARER, "<secret>"), (_EMAIL, "<email>"), (_UUID, "<id>"), (_IPV6, "<ip>"), (_IPV4, "<ip>"), (_LONG_HEX, "<id>"), (_LONG_TOKEN, "<secret>"), (_BIG_NUMBER, "<id>"), (_HOSTNAME, "<host>")):
        out = pattern.sub(placeholder, out)
    return out[:MAX_TEXT_CHARS * 4]


def scrub_value(value: Any, *, hosts: Iterable[str] = (), secrets: Iterable[str] = ()) -> Any:
    hosts, secrets = tuple(hosts), tuple(secrets)
    if isinstance(value, str):
        return scrub_text(value, hosts=hosts, secrets=secrets)
    if isinstance(value, Mapping):
        return {str(k): scrub_value(v, hosts=hosts, secrets=secrets) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [scrub_value(v, hosts=hosts, secrets=secrets) for v in value]
    return value


def label_for(verdict: str) -> str | None:
    return _VERDICT_TO_LABEL.get((verdict or "").upper())


def agrees(*, proposed: str, final: str, signals: Sequence[str]) -> bool:
    """Do the model's proposal and the recorded verdict tell one story?

    INCONCLUSIVE is treated as PASS. A FAIL may stand with or without a proving
    signal (the model's FAIL is enough). A PASS must have no proving signal
    (otherwise the guardrail would have raised it). The proposal must match
    what was recorded — the guardrail changing it is the disagreement left out.
    """
    def _norm(value: str) -> str:
        value = (value or "").upper()
        return "PASS" if value == "INCONCLUSIVE" else value

    final, proposed = _norm(final), _norm(proposed)
    if final not in _VERDICT_TO_LABEL or proposed != final:
        return False
    return True if final == "FAIL" else not signals


def rule_example(
    *, check_id: str, target: str, signals: Sequence[str], baseline: Mapping[str, Any], test: Mapping[str, Any], verdict: str, severity: str, confidence: str, finding: str,
    hosts: Iterable[str] = (), secrets: Iterable[str] = (),
) -> dict[str, Any]:
    """A provider-neutral `{task, input, output}` record for the `rule` task, scrubbed."""
    example = {
        "task": "rule",
        "input": {"check": check_id, "target": target, "signals": list(signals), "baseline": dict(baseline), "test": dict(test)},
        "output": {"verdict": verdict.upper(), "severity": severity.lower(), "confidence": confidence.upper(), "finding": finding},
    }
    return scrub_example(example, hosts=hosts, secrets=secrets)


def construct_example(
    *, endpoint: str, params: Sequence[Mapping[str, Any]], test: Mapping[str, Any], hosts: Iterable[str] = (), secrets: Iterable[str] = ()
) -> dict[str, Any]:
    """A `construct` record: the endpoint and parameters, and the (validated) test that proved an issue."""
    example = {
        "task": "construct",
        "input": {"endpoint": endpoint, "params": [dict(p) for p in params], "catalog_applicable": [test["check_id"]]},
        "output": {"tests": [dict(test)]},
    }
    return scrub_example(example, hosts=hosts, secrets=secrets)


def scrub_example(example: Mapping[str, Any], *, hosts: Iterable[str] = (), secrets: Iterable[str] = ()) -> dict[str, Any]:
    scrubbed = scrub_value(dict(example), hosts=hosts, secrets=secrets)
    for key in ("finding",):
        if key in scrubbed.get("output", {}):
            scrubbed["output"][key] = str(scrubbed["output"][key])[:MAX_TEXT_CHARS]
    return scrubbed


def balance(examples: Sequence[Mapping[str, Any]], labels: Sequence[str], *, seed: int = 0) -> list[Mapping[str, Any]]:
    """Downsample every label to the size of the smallest non-empty one (deterministically for a seed),
    so the dataset is not dominated by the most common outcome. Order within the result is stable."""
    by_label: dict[str, list[int]] = {}
    for index, label in enumerate(labels):
        by_label.setdefault(label, []).append(index)
    sizes = [len(v) for v in by_label.values() if v]
    if not sizes:
        return []
    keep = min(sizes)
    rng = random.Random(seed)
    chosen: list[int] = []
    for label in sorted(by_label):
        indices = list(by_label[label])
        rng.shuffle(indices)
        chosen += indices[:keep]
    return [examples[i] for i in sorted(chosen)]


def to_jsonl(examples: Iterable[Mapping[str, Any]]) -> str:
    return "".join(json.dumps(e, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n" for e in examples)


def dataset_version(examples: Sequence[Mapping[str, Any]], created: str) -> str:
    """`<UTC date>-<count>-<first 10 hex of the content hash>`: changes whenever the content does."""
    digest = hashlib.sha256(to_jsonl(examples).encode("utf-8")).hexdigest()[:10]
    return f"{created}-{len(examples)}-{digest}"
