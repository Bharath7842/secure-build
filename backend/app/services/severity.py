"""Standard-based severity for SAST findings: a CVSS v3.1 base score, its band.

The vector comes from, in order:

1. the catalog rule's own `cvss_vector`, when its pattern is narrower than its
   CWE (a browser-side API key is not a leaked server credential);
2. the CWE's baseline (`app/defaults/cwe_cvss.py`);
3. neither: the finding keeps the severity its rule or the model gave it.

Evidence the scanner has for this one finding then adjusts the vector — a
sanitizer on its taint path raises attack complexity, an authenticated entry
point raises the privileges required. Absence of evidence never lowers a score.
A quality issue is not a vulnerability (LOW, no score); code that is provably
never called keeps its score but is capped at LOW.

The rule's or model's severity is kept as `severity_basis.original_severity`,
and scoring always starts from it, so re-scoring is idempotent. DAST and SCA
findings are left alone (SCA already carries its advisory's CVSS).
"""

from __future__ import annotations

import json
import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping

from app.config import settings
from app.defaults.cwe_cvss import CWE_BASELINES, SCHEME
from app.services import cvss

logger = logging.getLogger(__name__)

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
UNSCORED_KINDS = frozenset({"dast", "sca"})
# Key formats that are public by design: browser/client keys a vendor documents as
# safe to ship, whose abuse depends on the restrictions set on them. A credential
# finding that matched one of these is not a leaked secret.
_PUBLISHABLE_KEY_RE = re.compile(
    r"\bAIza[0-9A-Za-z_\-]{35}"           # Google / Firebase API key
    r"|\bpk_(?:live|test)_[0-9A-Za-z]{10,}"  # Stripe publishable key
    r"|\bpk\.eyJ[0-9A-Za-z_\-]{10,}"       # Mapbox public token
)
_CREDENTIAL_CWES = frozenset({798})
_SEVERITY_FIELDS = ("severity", "cvss", "cvss_vector", "severity_basis")


def _get(row: Any, key: str) -> Any:
    return row.get(key) if isinstance(row, Mapping) else getattr(row, key, None)


def _cwe_number(value: Any) -> int | None:
    match = re.search(r"\d+", str(value or ""))
    return int(match.group()) if match else None


def _normalized_severity(value: Any) -> str:
    text = str(value or "").strip().upper()
    return text if text in SEVERITIES else "MEDIUM"


@lru_cache(maxsize=4)
def _rule_vectors(rules_dir: str) -> dict[str, str]:
    vectors: dict[str, str] = {}
    for path in sorted(Path(rules_dir).glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        rules = data if isinstance(data, list) else data.get("rules", []) if isinstance(data, dict) else []
        for rule in rules:
            if not isinstance(rule, dict) or not rule.get("id") or not rule.get("cvss_vector"):
                continue
            try:
                vectors[rule["id"]] = cvss.format_vector(cvss.parse(rule["cvss_vector"]))
            except cvss.CvssError as exc:
                logger.warning("rule %s has an invalid cvss_vector: %s", rule["id"], exc)
    return vectors


def rule_vectors() -> dict[str, str]:
    """{rule id: CVSS vector} for catalog rules that refine their CWE's baseline."""
    return _rule_vectors(str(Path(settings.sast_framework_path) / "rules"))


def score_finding(row: Any) -> dict[str, Any] | None:
    """{severity, cvss, cvss_vector, severity_basis} for a SAST finding (an ORM
    row or a finding dict), or None for a finding this scheme does not score."""
    if str(_get(row, "kind") or "").strip().lower() in UNSCORED_KINDS:
        return None
    prior = _get(row, "severity_basis") or {}
    original = _normalized_severity(prior.get("original_severity") or _get(row, "severity"))
    cwe = _cwe_number(_get(row, "cwe"))
    issue_class = str(_get(row, "issue_class") or "").strip().lower()
    basis: dict[str, Any] = {
        "scheme": SCHEME, "cwe": f"CWE-{cwe}" if cwe is not None else None,
        "original_severity": original, "adjustments": [],
    }

    if issue_class == "quality":
        basis.update(source="quality", note="code quality issue, not a vulnerability")
        return {"severity": "LOW", "cvss": None, "cvss_vector": None, "severity_basis": basis}

    rule_id = str(_get(row, "rule_id") or "")
    vector = rule_vectors().get(rule_id)
    if vector:
        basis["source"] = "rule"
    elif cwe is not None and cwe in CWE_BASELINES:
        vector = cvss.format_vector(cvss.parse(CWE_BASELINES[cwe][0]))
        basis.update(source="cwe", rationale=CWE_BASELINES[cwe][1])
    else:
        basis.update(source="original", note=(
            f"no CVSS baseline for {basis['cwe']}" if cwe is not None else "no CWE"
        ) + "; the rule's or model's severity is kept")
        return {"severity": original, "cvss": None, "cvss_vector": None, "severity_basis": basis}
    basis["baseline_vector"] = vector

    metrics = cvss.parse(vector)
    if cwe in _CREDENTIAL_CWES and any(
        _PUBLISHABLE_KEY_RE.search(str(_get(row, key) or "")) for key in ("matched_text", "snippet", "sink")
    ):
        vector = cvss.with_metrics(vector, C="L", I="N", A="N")
        basis["adjustments"].append({
            "metric": "C/I/A", "to": "L/N/N",
            "why": "a publishable client key (Google/Firebase, Stripe pk_, Mapbox pk.), public by design; "
                   "its risk depends on the restrictions set on it",
        })
    reachability = _get(row, "reachability") or {}
    if not isinstance(reachability, Mapping):
        reachability = {}
    if reachability.get("status") == "sanitized_path" and metrics["AC"] == "L":
        vector = cvss.with_metrics(vector, AC="H")
        basis["adjustments"].append({"metric": "AC", "to": "H", "why": "a sanitizer sits on the taint path"})
    if reachability.get("authenticated") is True and metrics["PR"] == "N":
        vector = cvss.with_metrics(vector, PR="L")
        basis["adjustments"].append(
            {"metric": "PR", "to": "L", "why": "the entry point requires an authenticated user"}
        )

    score = cvss.base_score(vector)
    severity = cvss.band(score)
    if issue_class == "inactive" and severity in ("CRITICAL", "HIGH", "MEDIUM"):
        severity = "LOW"
        basis["note"] = "the code is never called, so the severity is capped at LOW"
    return {"severity": severity, "cvss": score, "cvss_vector": vector, "severity_basis": basis}


def apply_severity(row: Any) -> bool:
    """Score `row` in place (ORM row or dict). True when anything changed."""
    scored = score_finding(row)
    if scored is None:
        return False
    changed = False
    for key in _SEVERITY_FIELDS:
        if _get(row, key) != scored[key]:
            changed = True
            if isinstance(row, dict):
                row[key] = scored[key]
            else:
                setattr(row, key, scored[key])
    return changed


def severity_basis_text(basis: Mapping[str, Any] | None) -> str:
    """One line for exports: where the severity came from."""
    if not basis:
        return ""
    source = basis.get("source")
    parts: list[str] = []
    if source == "rule":
        parts.append(f"rule-specific vector ({basis.get('cwe') or 'no CWE'})")
    elif source == "cwe":
        parts.append(f"{basis.get('cwe')} baseline: {basis.get('rationale', '')}".rstrip(": "))
    elif basis.get("note"):
        parts.append(str(basis["note"]))
    parts += [f"{a['metric']}:{a['to']} — {a['why']}" for a in basis.get("adjustments") or []]
    if source in ("rule", "cwe") and basis.get("note"):
        parts.append(str(basis["note"]))
    if basis.get("original_severity"):
        parts.append(f"was {basis['original_severity']}")
    return "; ".join(parts)
