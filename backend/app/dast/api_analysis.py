"""Helpers for the per-endpoint analysis record (what the analysis panel and the report read).

The test loop itself moved to `app/dast/active.py` (construct -> validate -> baseline -> test ->
detect -> rule -> roll-up): it is the only code that sends a test input, and only a validated one.
What remains here is the vocabulary around its results: the verdict names, the legacy target
shape, the deterministic overall roll-up and the mapping of an analysis record to finding rows
(used by the mock engine and for results stored before the loop existed).
"""

from __future__ import annotations

import json
from typing import Any, Optional
from urllib.parse import parse_qsl, urlsplit

# How many distinct REST APIs to analyze, and how many test cases to run per
# API, before stopping. Kept conservative: each test is a live request and each
# API costs two LLM round-trips (construction + ruling). Overridable via state.
DEFAULT_MAX_APIS = 15
DEFAULT_MAX_TESTS_PER_API = 12
MAX_PAYLOAD_CHARS = 200  # longer than this is discarded, however the model came by it

# Verdicts the per-check ruling may carry, in the DAST (PASS/FAIL/INCONCLUSIVE)
# vocabulary the spec and UI use. Mapped to the shared Finding verdict space by
# `_finding_verdict` below.
VERDICT_FAIL = "FAIL"
VERDICT_PASS = "PASS"
VERDICT_INCONCLUSIVE = "INCONCLUSIVE"
_VALID_VERDICTS = {VERDICT_FAIL, VERDICT_PASS, VERDICT_INCONCLUSIVE}

_SEVERITY_BY_NAME = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
_CONFIDENCE_FLOAT = {"HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.3}

# How much of a response body to keep as evidence / feed back to the ruling
# model. Enough to surface an error page or reflected payload, bounded so a
# large JSON/HTML body can't blow the prompt budget.
_RESPONSE_EVIDENCE_CHARS = 1500
_REQUEST_TIMEOUT_MS = 10_000


# ---------------------------------------------------------------------------
# Target construction
# ---------------------------------------------------------------------------


def build_api_target(api_call: dict, pages_data: list[dict] | None = None) -> dict[str, Any]:
    """Condense one discovered `api_call` into a target the model can reason about.

    Pulls query params out of the URL, notes the content type, and attaches any
    form on a crawled page whose action points at the same path (a hint at the
    request body shape, since the response listener only saw responses, not
    request bodies).
    """
    method = (api_call.get("method") or "GET").upper()
    url = api_call.get("url") or ""
    split = urlsplit(url)
    query_params = [k for k, _ in parse_qsl(split.query, keep_blank_values=True)]
    related_forms = []
    for page in pages_data or []:
        for form in page.get("forms") or []:
            action = str(form.get("action") or "")
            if action and (action in url or (split.path and split.path in action)):
                related_forms.append(
                    {
                        "method": form.get("method"),
                        "inputs": [
                            {"name": i.get("name"), "type": i.get("type")}
                            for i in (form.get("inputs") or [])
                        ],
                    }
                )
    return {
        "method": method,
        "url": url,
        "path": split.path,
        "query_params": query_params,
        "content_type": api_call.get("content_type") or "",
        "status_code": api_call.get("status_code"),
        "related_forms": related_forms[:3],
    }


def target_label(target: dict) -> str:
    """Human label used as the finding's `file_path` and the UI row title."""
    url = (target.get("url") or "").partition("#")[0].partition("?")[0]
    if url.startswith(("http://", "https://")):
        return f"{target.get('method', 'GET')} {url}"
    split = urlsplit(url)
    path = split.path or "/"
    return f"{target.get('method', 'GET')} {path}"


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def _norm_verdict(value: Any) -> str:
    v = str(value or "").strip().upper()
    if v == VERDICT_INCONCLUSIVE:
        return VERDICT_PASS
    return v if v in _VALID_VERDICTS else VERDICT_PASS


def _norm_severity(value: Any, verdict: str) -> str:
    v = str(value or "").strip().upper()
    if v in _SEVERITY_BY_NAME:
        return v
    return "INFO" if verdict == VERDICT_PASS else "MEDIUM"


def overall_verdict(checks: list[dict]) -> str:
    """Deterministic roll-up: any FAIL -> FAIL; otherwise PASS."""
    verdicts = {c["verdict"] for c in checks}
    if VERDICT_FAIL in verdicts:
        return VERDICT_FAIL
    return VERDICT_PASS


# ---------------------------------------------------------------------------
# Finding mapping
# ---------------------------------------------------------------------------


def _finding_verdict(check_verdict: str) -> Optional[str]:
    """Map a DAST check verdict into the shared Finding verdict space.

    FAIL -> true_positive, PASS (and leftover INCONCLUSIVE) -> None (a clean
    check is recorded in the analysis tree, not as a finding row)."""
    if check_verdict == VERDICT_FAIL:
        return "true_positive"
    return None


def _confidence_label(raw: Any) -> str:
    label = str(raw or "").strip().upper()
    return label if label in _CONFIDENCE_FLOAT else "LOW"


def finding_rows_from_analysis(api_result: dict) -> list[dict[str, Any]]:
    """Build Finding dicts (kind=dast) for the FAIL checks of one API.

    Shaped like the SAST engine's finding dicts so `_make_findings_writer`
    persists them unchanged and the existing findings panel/exports render
    them. The endpoint label is the `file_path`; the payload + response evidence
    is the `snippet`."""
    rows: list[dict[str, Any]] = []
    label = api_result.get("label") or ""
    for check in api_result.get("checks") or []:
        verdict = _finding_verdict(check["verdict"])
        if verdict is None:
            continue
        if str((check.get("response") or {}).get("error") or "").startswith("request not sent"):
            continue  # the guard refused it (e.g. a POST in safe mode): nothing was tested, so nothing to report
        snippet_parts = [
            f"Check: {check['check']}",
            f"Target: {check['target']} ({check.get('location') or 'query'})",
            f"Payload: {check['payload']}",
        ]
        if check["response"].get("status_code") is not None:
            snippet_parts.append(f"Response: HTTP {check['response']['status_code']}")
        if check.get("evidence"):
            snippet_parts.append(f"Evidence: {check['evidence']}")
        rows.append(
            {
                "severity": check["severity"],
                "cwe": check["cwe"],
                "owasp_category": check["owasp_category"],
                "rule_id": check["check_id"],
                "title": f"{check['check']} — {label}",
                "file_path": label,
                "line": None,
                "snippet": "\n".join(snippet_parts),
                "kind": "dast",
                "verdict": verdict,
                "confidence": _CONFIDENCE_FLOAT.get(check.get("confidence", ""), 0.5),
                "source": check["target"],
                "sink": api_result.get("url"),
                "verdict_reason": check.get("finding") or "",
                # DAST evidence fields (persisted to the dedicated Finding columns).
                "target": label,
                "param": check["target"],
                "location": check.get("location") or "query",
                "confidence_label": _confidence_label(check.get("confidence")),
            }
        )
    return rows
