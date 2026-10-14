"""Deterministic verdict for the scanner's "session was lost" claim.

The assessment is intentionally built from the durable scan log rather than
page appearance alone.  It is small enough to rebuild on every narration read
and contains no credentials, cookies, response bodies, or model scratchpad.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib.parse import unquote, urlsplit


_SESSION_LOST_RE = re.compile(r"\[session_lost\]\s*(.+)$", re.IGNORECASE)
_ENDPOINT_RE = re.compile(
    r"^\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(https?://\S+)\s+"
    r"\(status\s+(\d{3}),\s*([^)]*)\)",
    re.IGNORECASE,
)
_VISITED_RE = re.compile(r"after visiting\s+(https?://\S+)", re.IGNORECASE)
_CRAWL_START_RE = re.compile(r"\[4/4\]\s+(?:Starting|Resuming) crawl", re.IGNORECASE)
_AUTH_SEGMENTS = {"login", "logout", "signin", "signout", "auth", "session", "current-user", "me", "token"}
_ALGORITHM_VERSION = "session-verdict-v1"


def _path(url: str) -> str:
    try:
        return unquote(urlsplit(url).path) or "/"
    except ValueError:
        return "/"


def _is_auth_control(url: str) -> bool:
    segments = {segment.lower() for segment in _path(url).split("/") if segment}
    return bool(segments & _AUTH_SEGMENTS)


def _is_application_json(url: str, status: int, content_type: str) -> bool:
    return (
        200 <= status < 300
        and "json" in content_type.lower()
        and _path(url).lower().startswith("/api/")
        and not _is_auth_control(url)
    )


def _short_request(method: str, url: str, status: int, content_type: str = "") -> str:
    suffix = " application/json" if "json" in content_type.lower() else ""
    return f"{method.upper()} {_path(url)} returned HTTP {status}{suffix}."


def assess_session_loss(log_lines: list[str]) -> dict[str, Any] | None:
    """Return one binary assessment for the first unique session-loss claim.

    A successful application-data response is stronger than a login-shaped UI.
    A successful explicit logout or transport denial is proof that the session
    really was invalidated. Repeated warning lines in a later crawl summary are
    deliberately ignored so newer unrelated traffic cannot rewrite history.
    """
    warning_index = -1
    warning_detail = ""
    for index, line in enumerate(log_lines, start=1):
        match = _SESSION_LOST_RE.search(line)
        if match:
            warning_index = index
            warning_detail = match.group(1).strip()
            break
    if warning_index < 0:
        return None

    start_index = 1
    for index, line in enumerate(log_lines[: warning_index - 1], start=1):
        if _CRAWL_START_RE.search(line):
            start_index = index

    observations: list[dict[str, Any]] = []
    for index, line in enumerate(log_lines[start_index: warning_index - 1], start=start_index + 1):
        match = _ENDPOINT_RE.match(line)
        if not match:
            continue
        method, url, status_text, content_type = match.groups()
        status = int(status_text)
        if method.upper() == "POST" and _path(url).lower().rstrip("/").endswith("/logout") and 200 <= status < 300:
            observations.append(
                {"kind": "logout", "index": index, "detail": _short_request(method, url, status, content_type)}
            )
        elif _is_application_json(url, status, content_type):
            observations.append(
                {"kind": "application", "index": index, "detail": _short_request(method, url, status, content_type)}
            )
        elif status in (401, 403):
            observations.append(
                {"kind": "denial", "index": index, "detail": _short_request(method, url, status, content_type)}
            )

    decisive = max(observations, key=lambda item: item["index"], default=None)
    visited = _VISITED_RE.search(warning_detail)
    visited_path = _path(visited.group(1)) if visited else "the page"
    warning_evidence = f"The browser returned to a login-shaped page after {visited_path}."

    if decisive and decisive["kind"] == "application":
        verdict = "false_positive"
        reason_code = "application_data_succeeded"
        why = "Application data still succeeded after the page looked signed out."
        evidence = [decisive["detail"], warning_evidence]
    elif decisive and decisive["kind"] == "logout":
        verdict = "true_positive"
        reason_code = "logout_succeeded"
        why = "The application accepted a logout request, so the signed-in session was actually invalidated."
        evidence = [decisive["detail"], warning_evidence]
    elif decisive and decisive["kind"] == "denial":
        verdict = "true_positive"
        reason_code = "requests_rejected"
        why = "The application rejected the signed-in request and no newer application-data success was recorded."
        evidence = [decisive["detail"], warning_evidence]
    else:
        # The crawler only emits this claim after it has verified the login-shaped
        # state. With no contrary application-data evidence, keep the product's
        # requested binary verdict and make the evidence limitation explicit.
        verdict = "true_positive"
        reason_code = "login_state_confirmed"
        why = "The browser returned to the verified login state and no newer application-data success was recorded."
        evidence = [warning_evidence]

    canonical = {
        "version": _ALGORITHM_VERSION,
        "event_order": warning_index,
        "warning": warning_detail,
        "observations": observations,
        "verdict": verdict,
    }
    fingerprint = hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()[:16]
    return {
        "claim": "The signed-in session was lost",
        "verdict": verdict,
        "why": why,
        "evidence": evidence[:3],
        "reason_code": reason_code,
        "confidence": None,
        "source": "rules",
        "provider": None,
        "model": None,
        "event_order": warning_index,
        "fingerprint": fingerprint,
        "algorithm_version": _ALGORITHM_VERSION,
    }
