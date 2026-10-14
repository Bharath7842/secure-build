"""Evidence-based validation of hunt candidates.

1. Grounding (deterministic). The sink — and the source, when the class
   needs one — must lie in spans a tool actually showed the investigator
   (EvidenceLedger), and every quoted line must match the file (allowing for
   the redaction the model saw). Anything else was invented: dropped.
2. Evidence level.
     L3  a Joern taint path covers source -> sink;
     L2  every cross-method hop resolved by the call graph (or Joern), the
         source is a request accessor / framework-entry parameter, and the
         sink is a known sink (graph-resolved or catalog-matched);
     L1  anything weaker — a textual hop, an unproven source.
   A regex match is navigation, never proof: it can only produce L1.
3. Independent verification. L2/L3 candidates are re-judged by a fresh LLM
   call that never sees the investigator's transcript — flow_verify for
   source->sink classes, the group-confirm prompt for single-construct
   (configuration) classes.
4. Verdict caps. true_positive needs L2/L3 *and* verifier agreement; L1 or
   any disagreement yields `unverified`, with the reason stated.
5. Dedupe on the finding, not the tier: a candidate matching an existing
   finding (same file, sink line +-2, CWE family) is `corroborated`, not
   re-published — including findings in CRITICAL files the deep scan
   already reported, while ones it missed are published.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from pipeline import flow_verify
from pipeline.call_graph import Flow, FlowHop
from pipeline.hunt import catalog
from pipeline.hunt.evidence import (
    RESOLUTION_GRAPH,
    RESOLUTION_JOERN,
    RESOLUTION_READ,
    RESOLUTION_TEXTUAL,
    EvidenceLedger,
    resolution_strength,
)
from pipeline.hunt.redact import redact, redaction_aware_equal
from pipeline.hunt.symbols import SymbolService
from pipeline.hunt.tools import HuntToolbox
from pipeline.llm_file_scan import (
    _TAINT_SOURCE_RE,
    VERDICT_UNVERIFIED,
    build_code_context,
    confirm_finding_group,
    normalize_finding,
    should_publish_finding,
)

LEVEL_L1 = "L1"
LEVEL_L2 = "L2"
LEVEL_L3 = "L3"
QUOTE_SLACK = 3
DEDUPE_LINE_SLACK = 2
BODY_WINDOW = 15
READ_SPAN_MAX_LINES = 60

STATUS_PUBLISHED = "published"
STATUS_CORROBORATED = "corroborated"
STATUS_HALLUCINATED = "dropped_hallucinated"
STATUS_OUT_OF_SCOPE = "dropped_out_of_scope"
STATUS_SUPPRESSED = "suppressed"

CONFIG_KINDS = frozenset({"crypto", "secret", "csrf"})

# CWE ids that describe the same weakness for dedupe purposes.
_CWE_FAMILIES = [
    {"CWE-89", "CWE-564", "CWE-943", "CWE-90"},
    {"CWE-79", "CWE-80", "CWE-83", "CWE-116"},
    {"CWE-22", "CWE-23", "CWE-36", "CWE-73"},
    {"CWE-77", "CWE-78", "CWE-88"},
    {"CWE-117", "CWE-93"},
    {"CWE-798", "CWE-259", "CWE-321"},
    {"CWE-327", "CWE-328", "CWE-330", "CWE-338"},
    {"CWE-862", "CWE-285", "CWE-284", "CWE-863"},
    {"CWE-611", "CWE-776"},
]


def cwe_family(cwe: Optional[str]) -> str:
    norm = str(cwe or "").strip().upper()
    for i, fam in enumerate(_CWE_FAMILIES):
        if norm in fam:
            return f"family{i}"
    return norm


@dataclass
class ExistingFindings:
    """Findings the other tiers already wrote, for finding-level dedupe."""
    by_file: Dict[str, List[Tuple[int, str, str]]] = field(default_factory=dict)

    @classmethod
    def from_file_results(cls, file_results: Iterable[Dict[str, Any]]) -> "ExistingFindings":
        idx: Dict[str, List[Tuple[int, str, str]]] = {}
        for fr in file_results:
            path = fr.get("file_path") or ""
            for f in fr.get("findings") or []:
                fp = f.get("file_path") or path
                try:
                    line = int(f.get("line") or 0)
                except (TypeError, ValueError):
                    continue
                idx.setdefault(fp, []).append(
                    (line, cwe_family(f.get("cwe")), f"{f.get('kind') or 'llm'}:{f.get('rule_id') or ''}:{line}")
                )
        return cls(by_file=idx)

    def match(self, file: str, line: int, cwe: Optional[str]) -> Optional[str]:
        fam = cwe_family(cwe)
        for existing_line, existing_fam, ident in self.by_file.get(file, []):
            if existing_fam == fam and abs(existing_line - line) <= DEDUPE_LINE_SLACK:
                return ident
        return None

    def add(self, file: str, line: int, cwe: Optional[str], ident: str) -> None:
        self.by_file.setdefault(file, []).append((line, cwe_family(cwe), ident))


@dataclass
class ValidationOutcome:
    status: str
    evidence_level: Optional[str] = None
    finding: Optional[Dict[str, Any]] = None
    reasons: List[str] = field(default_factory=list)
    corroborates: Optional[str] = None
    verifier: Optional[str] = None  # agree | disagree | unavailable | skipped


def _loc(raw: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, dict):
        return None
    try:
        line = int(raw.get("line"))
    except (TypeError, ValueError):
        return None
    file = str(raw.get("file") or "").strip()
    if not file or line <= 0:
        return None
    return {"file": file, "line": line, "expr": str(raw.get("expr") or "")[:300],
            "method": str(raw.get("method") or "")[:200], "role": str(raw.get("role") or "")}


def _compile_all(patterns: Sequence[str]) -> List["re.Pattern[str]"]:
    out = []
    for p in patterns:
        try:
            out.append(re.compile(p))
        except re.error:
            continue
    return out


class Validator:
    def __init__(
        self,
        *,
        toolbox: HuntToolbox,
        symbols: SymbolService,
        existing: ExistingFindings,
        llm: Optional[Callable[..., str]] = None,
        stack_context: str = "",
        suppress_no_cwe: bool = True,
        suppress_http_findings: bool = False,
        suppress_low_confidence_false_positives: bool = False,
    ) -> None:
        self.toolbox = toolbox
        self.symbols = symbols
        self.existing = existing
        self.llm = llm
        self.stack_context = stack_context
        self.suppress = {
            "suppress_no_cwe": suppress_no_cwe,
            "suppress_http_findings": suppress_http_findings,
            "suppress_low_confidence_false_positives": suppress_low_confidence_false_positives,
        }
        self._source_res = _compile_all(catalog.source_patterns())

    # -- public ------------------------------------------------------------

    def validate(self, candidate: Dict[str, Any], ledger: EvidenceLedger) -> ValidationOutcome:
        hyp = candidate.get("_hypothesis") or {}
        kind = str(hyp.get("sink_kind") or "")
        needs_source = bool(hyp.get("needs_source", kind not in CONFIG_KINDS))
        access_control = bool(hyp.get("access_control"))
        cwe = str(candidate.get("cwe") or hyp.get("cwe") or "").strip().upper() or None

        sink = _loc(candidate.get("sink"))
        if sink is None:
            return ValidationOutcome(STATUS_HALLUCINATED, reasons=["no sink location"])
        if self.toolbox._in_scope(sink["file"]) is None:
            return ValidationOutcome(STATUS_OUT_OF_SCOPE, reasons=[f"{sink['file']} is not in the scan scope"])

        # 1. grounding
        reasons: List[str] = []
        sink = self._reanchor(sink)
        if not ledger.covers(sink["file"], sink["line"], slack=2):
            return ValidationOutcome(STATUS_HALLUCINATED, reasons=[f"sink {sink['file']}:{sink['line']} was never shown to the investigator"])
        bad_quote = self._first_bad_quote(candidate.get("quoted_lines") or [])
        if bad_quote:
            return ValidationOutcome(STATUS_HALLUCINATED, reasons=[bad_quote])
        source = _loc(candidate.get("source")) if needs_source and not access_control else None
        if source is not None:
            if self.toolbox._in_scope(source["file"]) is None:
                return ValidationOutcome(STATUS_OUT_OF_SCOPE, reasons=[f"source {source['file']} is out of scope"])
            source = self._reanchor(source)
            if not ledger.covers(source["file"], source["line"], slack=2):
                return ValidationOutcome(STATUS_HALLUCINATED, reasons=[f"source {source['file']}:{source['line']} was never shown to the investigator"])
        path = [p for p in (_loc(p) for p in (candidate.get("path") or [])) if p and self.toolbox._in_scope(p["file"])]

        # 2. evidence level
        level, level_reasons = self._evidence_level(
            kind=kind, needs_source=needs_source, access_control=access_control,
            sink=sink, source=source, path=path, ledger=ledger,
            gaps=list(candidate.get("_evidence_gaps") or []),
        )
        reasons += level_reasons

        # 5 (early). dedupe before spending a verifier call
        duplicate = self.existing.match(sink["file"], sink["line"], cwe)
        if duplicate:
            return ValidationOutcome(STATUS_CORROBORATED, evidence_level=level, reasons=reasons, corroborates=duplicate)

        # 3. independent verification (only where a TP is still possible)
        verifier = "skipped"
        verifier_reason = ""
        if level in (LEVEL_L2, LEVEL_L3) and self.llm is not None:
            verifier, verifier_reason = self._verify(candidate, kind=kind, sink=sink, source=source, path=path, cwe=cwe)

        # 4. verdict caps
        hunter_tp = str(candidate.get("verdict") or "").lower().startswith("true")
        if hunter_tp and level in (LEVEL_L2, LEVEL_L3) and verifier == "agree":
            verdict = "true_positive"
            reason = str(candidate.get("verdict_reason") or verifier_reason or "")
        else:
            verdict = VERDICT_UNVERIFIED
            if level == LEVEL_L1:
                why = "; ".join(level_reasons) or "evidence below the confirmation bar"
                reason = f"Evidence level L1 — {why}. Needs manual review."
            elif verifier == "disagree":
                reason = f"Independent verifier disagreed: {verifier_reason or 'no vulnerability found'}."
            else:
                reason = "Not independently verified (verifier unavailable or over budget)."

        finding = self._build_finding(candidate, cwe=cwe, sink=sink, source=source, path=path,
                                      verdict=verdict, reason=reason, level=level)
        if finding is None:
            return ValidationOutcome(STATUS_SUPPRESSED, evidence_level=level, reasons=reasons + ["could not normalize"])
        context = self._context_text(sink)
        if not should_publish_finding(finding, context, **self.suppress):
            return ValidationOutcome(STATUS_SUPPRESSED, evidence_level=level, finding=finding,
                                     reasons=reasons + ["publish gate (CWE/HTTP/low-confidence rules)"], verifier=verifier)
        self.existing.add(sink["file"], sink["line"], cwe, f"hunt:{finding['rule_id']}:{sink['line']}")
        return ValidationOutcome(STATUS_PUBLISHED, evidence_level=level, finding=finding, reasons=reasons, verifier=verifier)

    # -- grounding ---------------------------------------------------------

    def _lines(self, file: str) -> List[str]:
        return self.toolbox._lines(file) or []

    def _reanchor(self, loc: Dict[str, Any]) -> Dict[str, Any]:
        """Snap a cited line to where its quoted expression actually is (+-3)."""
        expr = " ".join(str(loc.get("expr") or "").split())
        lines = self._lines(loc["file"])
        if not expr or len(expr) < 4 or not lines:
            return loc
        line = loc["line"]
        for delta in sorted(range(-QUOTE_SLACK, QUOTE_SLACK + 1), key=abs):
            ln = line + delta
            if 1 <= ln <= len(lines):
                actual = " ".join(lines[ln - 1].split())
                if expr in actual or expr in " ".join(redact(lines[ln - 1]).split()):
                    return {**loc, "line": ln}
        return loc

    def _first_bad_quote(self, quotes: Sequence[Any]) -> Optional[str]:
        for q in quotes:
            if not isinstance(q, dict):
                continue
            loc = _loc(q)
            text = str(q.get("text") or "")
            if loc is None or not text.strip():
                continue
            if self.toolbox._in_scope(loc["file"]) is None:
                return f"quoted file {loc['file']} is not in the scan scope"
            lines = self._lines(loc["file"])
            window = range(max(1, loc["line"] - QUOTE_SLACK), min(len(lines), loc["line"] + QUOTE_SLACK) + 1)
            if not any(redaction_aware_equal(text, lines[ln - 1]) for ln in window):
                return f"quoted line {loc['file']}:{loc['line']} does not match the file"
        return None

    # -- evidence level ------------------------------------------------------

    def _line_text(self, loc: Dict[str, Any]) -> str:
        lines = self._lines(loc["file"])
        return lines[loc["line"] - 1] if 0 < loc["line"] <= len(lines) else ""

    def _sink_known(self, kind: str, sink: Dict[str, Any]) -> bool:
        if self.symbols.graph_sink_kind(sink["file"], sink["line"]):
            return True
        text = self._line_text(sink)
        return any(r.search(text) for r in _compile_all(catalog.sink_patterns().get(kind, [])))

    def _source_untrusted(self, source: Dict[str, Any]) -> bool:
        text = self._line_text(source)
        if _TAINT_SOURCE_RE.search(text) or any(r.search(text) for r in self._source_res):
            return True
        return self.symbols.is_framework_entry_at(source["file"], source["line"])

    def _hop_resolution(self, a: Dict[str, Any], b: Dict[str, Any], ledger: EvidenceLedger) -> Optional[str]:
        """How the step a -> b is established: same method (graph), a
        resolved call edge (graph/joern), or only a textual guess."""
        if a["file"] == b["file"]:
            ma = self.symbols.enclosing_method(a["file"], a["line"])
            mb = self.symbols.enclosing_method(b["file"], b["line"])
            if ma is not None and mb is not None and ma.key == mb.key:
                return RESOLUTION_GRAPH
            if ma is None and mb is None:
                lo, hi = sorted((a["line"], b["line"]))
                if hi - lo <= READ_SPAN_MAX_LINES and all(ledger.covers(a["file"], ln) for ln in range(lo, hi + 1)):
                    return RESOLUTION_READ
                return RESOLUTION_TEXTUAL
            # Two different methods in one file: still needs a resolved call.
        resolved = self.symbols.edge_resolution(caller_file=a["file"], call_line=a["line"], callee_file=b["file"])
        if resolved:
            return resolved
        observed = ledger.best_edge(caller_file=a["file"], callee_file=b["file"])
        return observed.resolution if observed else None

    def _evidence_level(
        self, *, kind: str, needs_source: bool, access_control: bool, sink: Dict[str, Any],
        source: Optional[Dict[str, Any]], path: List[Dict[str, Any]], ledger: EvidenceLedger, gaps: List[str],
    ) -> Tuple[str, List[str]]:
        reasons: List[str] = []
        if gaps:
            reasons.append("investigation reported with open gaps: " + "; ".join(g.split(":", 1)[0] for g in gaps))
        if kind in CONFIG_KINDS or not needs_source:
            if not self._sink_known(kind, sink):
                reasons.append("offending line does not match a known pattern for this class")
            return (LEVEL_L2 if not reasons else LEVEL_L1), reasons
        if access_control:
            if not self.symbols.is_framework_entry_at(sink["file"], sink["line"]):
                reasons.append("endpoint not resolved as a framework entry method")
            return (LEVEL_L2 if not reasons else LEVEL_L1), reasons

        if source is None:
            return LEVEL_L1, reasons + ["no untrusted source established"]
        if not self._sink_known(kind, sink):
            reasons.append("sink is not a known/graph-resolved sink call")
        if not self._source_untrusted(source):
            reasons.append("source not proven untrusted (not a request accessor or entry-point parameter)")
        if self.symbols.joern_covers(source_file=source["file"], source_line=source["line"],
                                     sink_file=sink["file"], sink_line=sink["line"]):
            return (LEVEL_L3 if not reasons else LEVEL_L1), reasons

        chain: List[Dict[str, Any]] = []
        for loc in [source] + path + [sink]:
            if not chain or (chain[-1]["file"], chain[-1]["line"]) != (loc["file"], loc["line"]):
                chain.append(loc)
        weakest = 3
        for a, b in zip(chain, chain[1:]):
            res = self._hop_resolution(a, b, ledger)
            strength = resolution_strength(res)
            weakest = min(weakest, strength)
            if strength < resolution_strength(RESOLUTION_GRAPH):
                reasons.append(
                    f"hop {a['file'].rsplit('/', 1)[-1]}:{a['line']} -> {b['file'].rsplit('/', 1)[-1]}:{b['line']} "
                    + ("is only a textual match" if res else "is not resolved")
                )
        unobserved = [p for p in path if not ledger.covers(p["file"], p["line"], slack=2)]
        if unobserved:
            reasons.append(f"{len(unobserved)} path hop(s) never shown to the investigator")
        if reasons:
            return LEVEL_L1, reasons
        return (LEVEL_L3 if weakest >= resolution_strength(RESOLUTION_JOERN) else LEVEL_L2), reasons

    # -- independent verifier -------------------------------------------------

    def _hop_for(self, loc: Dict[str, Any], role: str) -> FlowHop:
        method = self.symbols.enclosing_method(loc["file"], loc["line"])
        if method is not None:
            return FlowHop(
                file=loc["file"], method=f"{method.fqcn}.{method.name}", fqcn=method.fqcn, name=method.name,
                line=loc["line"], start_line=method.start_line, end_line=method.end_line,
                body=redact(method.body), role=role, label=redact(loc.get("expr") or f"{method.name}(...)"),
            )
        lines = self._lines(loc["file"])
        start = max(1, loc["line"] - BODY_WINDOW)
        end = min(len(lines), loc["line"] + BODY_WINDOW)
        return FlowHop(
            file=loc["file"], method=f"lines {start}-{end}", fqcn="", name="", line=loc["line"],
            start_line=start, end_line=end, body=redact("\n".join(lines[start - 1:end])), role=role,
            label=redact(loc.get("expr") or ""),
        )

    def _verify(
        self, candidate: Dict[str, Any], *, kind: str, sink: Dict[str, Any],
        source: Optional[Dict[str, Any]], path: List[Dict[str, Any]], cwe: Optional[str],
    ) -> Tuple[str, str]:
        try:
            if source is None:
                return self._verify_construct(candidate, kind=kind, sink=sink, cwe=cwe)
            hops: List[FlowHop] = []
            for loc, role in [(source, "source")] + [(p, "hop") for p in path] + [(sink, "sink")]:
                hop = self._hop_for(loc, role)
                if hops and (hops[-1].file, hops[-1].start_line) == (hop.file, hop.start_line):
                    # Consecutive points in one method are one hop; the sink
                    # role (and its line) wins.
                    if role == "sink":
                        hops[-1].role, hops[-1].line, hops[-1].label = "sink", hop.line, hop.label
                    continue
                hops.append(hop)
            flow = Flow(hops=hops, entry_tier="hunt", sink_kind=kind or "other", authenticated=False,
                        files=list(dict.fromkeys(h.file for h in hops)))
            result = flow_verify.verify_flows(
                [flow], stack_context=self.stack_context, usage=None, call_llm_fn=self.llm,
                findings_writer=None, cap=1, flows_per_call=1, llm_step="hunt_verify",
                suppress_no_cwe=False, suppress_http_findings=False,
                suppress_low_confidence_false_positives=False,
            )
        except Exception as exc:  # noqa: BLE001
            return "unavailable", f"{type(exc).__name__}"
        if result.get("flows_failed"):
            return "unavailable", "verifier response unusable"
        findings = result.get("findings") or []
        tps = [f for f in findings if f.get("verdict") == "true_positive"]
        if tps:
            return "agree", str(tps[0].get("verdict_reason") or "")
        if findings:
            return "disagree", str(findings[0].get("verdict_reason") or "")
        return "disagree", "verifier reported no vulnerability on this path"

    def _verify_construct(
        self, candidate: Dict[str, Any], *, kind: str, sink: Dict[str, Any], cwe: Optional[str],
    ) -> Tuple[str, str]:
        text = "\n".join(self._lines(sink["file"]))
        representative = {
            "rule_id": f"hunt-{(cwe or 'cwe').lower()}",
            "title": str(candidate.get("title") or ""),
            "cwe": cwe,
            "line": sink["line"],
            "matched_text": redact(self._line_text(sink).strip())[:200],
            "verdict": VERDICT_UNVERIFIED,
        }
        decision = confirm_finding_group(
            representative=representative, occurrence_paths=[sink["file"]], source_text=redact(text),
            rule=None, stack_context=self.stack_context, usage=None, call_llm_fn=self.llm,
        )
        verdict = decision.get("verdict")
        if decision.get("error") or verdict == VERDICT_UNVERIFIED:
            return "unavailable", str(decision.get("error") or "")
        return ("agree" if verdict == "true_positive" else "disagree"), str(decision.get("verdict_reason") or "")

    # -- finding --------------------------------------------------------------

    def _flow_step(self, step: int, loc: Dict[str, Any], role: str) -> Dict[str, Any]:
        """One flow_path entry in flow_verify's payload shape, with this
        hop's own code window so the UI trace shows each step's code."""
        lines = self._lines(loc["file"])
        method = self.symbols.enclosing_method(loc["file"], loc["line"])
        if method is not None and method.end_line - method.start_line <= 60:
            start, end = method.start_line, method.end_line
        else:
            start, end = max(1, loc["line"] - 6), min(len(lines), loc["line"] + 6)
        return {
            "step": step,
            "file": loc["file"],
            "line": loc["line"],
            "start_line": start,
            "method": (f"{method.fqcn.rsplit('.', 1)[-1]}.{method.name}" if method is not None else loc.get("method") or ""),
            "role": role,
            "label": loc.get("expr") or "",
            "snippet": "\n".join(lines[start - 1:end]),
        }

    def _context_text(self, sink: Dict[str, Any]) -> str:
        lines = self._lines(sink["file"])
        lo, hi = max(1, sink["line"] - 10), min(len(lines), sink["line"] + 10)
        return "\n".join(lines[lo - 1:hi])

    def _build_finding(
        self, candidate: Dict[str, Any], *, cwe: Optional[str], sink: Dict[str, Any],
        source: Optional[Dict[str, Any]], path: List[Dict[str, Any]], verdict: str, reason: str, level: str,
    ) -> Optional[Dict[str, Any]]:
        sink_text = self._line_text(sink).strip()
        chain = ([source] if source else []) + path + [sink]
        data_flow = " -> ".join(f"{c['file'].rsplit('/', 1)[-1]}:{c['line']}" for c in chain)
        raw = {
            "verdict": verdict,
            "confidence": candidate.get("confidence"),
            "severity": candidate.get("severity"),
            "cwe": cwe,
            "rule_id": f"hunt-{(cwe or 'unknown').lower()}",
            "title": candidate.get("title"),
            "line": sink["line"],
            "source": (f"{source['file']}:{source['line']} {source.get('expr') or ''}".strip() if source else ""),
            "sink": f"{sink['file']}:{sink['line']} {sink.get('expr') or sink_text[:120]}".strip(),
            "data_flow": f"{data_flow} [evidence {level}]",
            "snippet": sink_text,
            "verdict_reason": reason,
            "ai_fix": candidate.get("ai_fix"),
            "kind": "hunt",
        }
        lines = self._lines(sink["file"])
        finding = normalize_finding(
            raw, file_path=sink["file"], chunk_start=max(1, sink["line"] - 3),
            chunk_end=min(len(lines) or sink["line"], sink["line"] + 3), source_lines=lines, kind="hunt",
        )
        if finding is None:
            return None
        finding["line"] = sink["line"]
        finding["snippet"] = build_code_context("\n".join(lines), sink["line"], sink_text)
        finding["matched_text"] = " ".join(sink_text.split())[:160]
        finding["group_by_rule"] = False
        finding["affected_files"] = list(dict.fromkeys(c["file"] for c in chain))
        finding["flow_path"] = [
            self._flow_step(i, c, "source" if (source is not None and i == 1) else ("sink" if i == len(chain) else "hop"))
            for i, c in enumerate(chain, start=1)
        ]
        finding["evidence_level"] = level
        return finding
