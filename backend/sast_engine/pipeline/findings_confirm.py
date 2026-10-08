"""findings_confirm.py — heuristic pre-LLM confirmation gate for AST findings.

Runs between `node_ast_pattern_queries` and `node_llm_verify_ast`. LLM calls
cost money and time, so not every raw AST-pattern match should be spent on
one: CRITICAL/HIGH severity findings are trustworthy enough on their own
(auto-pass), while MEDIUM/LOW findings need corroborating evidence — this
module is that corroboration check, and it is what answers "who confirms
findings before the LLM sees them?".
"""

from __future__ import annotations

from typing import Any, Dict, List

_AUTO_PASS_SEVERITIES = {"CRITICAL", "HIGH"}
_CONFIRM_THRESHOLD = 0.5

_DANGEROUS_FUNCS = (
    "executeQuery", "executeUpdate", "exec", "eval", "system",
    "Runtime.getRuntime", "ProcessBuilder", "pickle.loads",
)
_AUTH_MARKERS = ("@PreAuthorize", "@Secured", "@RolesAllowed", "requires_auth", "login_required")
_ENTRYPOINT_MARKERS = ("@PostMapping", "@GetMapping", "@RequestMapping", "@app.route", "router.")


def _score_finding(finding: Dict[str, Any], findings: List[Dict[str, Any]]) -> tuple[float, List[str]]:
    score = 0.0
    evidence: List[str] = []

    same_spot = [
        f for f in findings
        if f is not finding
        and f["file_path"] == finding["file_path"]
        and f["line_number"] == finding["line_number"]
    ]
    if same_spot:
        score += 0.3
        evidence.append(f"corroborated_by_{len(same_spot)}_other_pattern(s)_at_same_line")

    snippet = finding.get("code_snippet") or ""
    if any(func in snippet for func in _DANGEROUS_FUNCS):
        score += 0.3
        evidence.append("dangerous_function_call_in_snippet")

    if any(m in snippet for m in _ENTRYPOINT_MARKERS) and not any(m in snippet for m in _AUTH_MARKERS):
        score += 0.2
        evidence.append("entrypoint_context_without_auth_guard")

    if finding.get("cvss") and float(finding["cvss"]) >= 8.0:
        score += 0.2
        evidence.append("cvss_high")

    return score, evidence


def node_findings_confirm(state: Dict[str, Any]) -> dict:
    tracer = state["_tracer"]
    findings = state.get("ast_findings") or []

    confirmed: List[Dict[str, Any]] = []
    discarded: List[Dict[str, Any]] = []

    for finding in findings:
        severity = (finding.get("severity") or "").upper()
        if severity in _AUTO_PASS_SEVERITIES:
            finding["confirmation_score"] = 1.0
            finding["confirmation_method"] = "severity_auto_pass"
            finding["confirmation_evidence"] = [f"severity={severity}"]
            confirmed.append(finding)
            continue

        score, evidence = _score_finding(finding, findings)
        finding["confirmation_score"] = round(score, 2)
        finding["confirmation_method"] = "heuristic"
        finding["confirmation_evidence"] = evidence

        if score >= _CONFIRM_THRESHOLD:
            confirmed.append(finding)
        else:
            discarded.append(finding)

    tracer.log(5, "findings_confirm",
                f"Pre-LLM confirmation: {len(confirmed)} confirmed, {len(discarded)} discarded "
                f"(of {len(findings)} raw finding(s))",
                detail=f"auto_pass={sum(1 for f in confirmed if f['confirmation_method'] == 'severity_auto_pass')}, "
                       f"heuristic_pass={sum(1 for f in confirmed if f['confirmation_method'] == 'heuristic')}",
                narrative=f"Confirmed {len(confirmed)}/{len(findings)} finding(s) for LLM review "
                          f"({len(discarded)} discarded as low-confidence).")

    return {"confirmed_findings": confirmed, "discarded_findings": discarded}
