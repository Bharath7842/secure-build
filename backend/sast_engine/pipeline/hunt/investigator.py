"""Per-hypothesis investigation loop: an LLM researcher driving read-only
tools one JSON action at a time, with the engine — not the model — deciding
what has actually been established.

The engine keeps an evidence checklist per hypothesis (sink located, source
located, path between them, data flow read, sanitizers checked,
authorization checked). The model's "evidence" notes only update it when the
cited line is something a tool actually showed (EvidenceLedger). From the
checklist the engine computes the next strategy and enforces it:

* `report` with gaps is refused once or twice with INSUFFICIENT_EVIDENCE and
  the list of what is missing — a sink is not a vulnerability;
* after that refusal, or after 3 consecutive searches for an item already
  established, further searches for it are blocked and the model is pointed
  at the strategy for the first missing item (e.g. sink found but no source
  -> trace callers and parameters instead of another sink regex).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from llm_client import parse_llm_json_dict
from pipeline.hunt import catalog
from pipeline.hunt.evidence import EvidenceLedger
from pipeline.hunt.llm import HuntBudgetExceeded
from pipeline.hunt.planner import (
    CONFIG_KINDS,
    STRATEGY_CONFIG_FIRST,
    STRATEGY_SOURCE_FIRST,
    Hypothesis,
)
from pipeline.hunt.prompts import HUNT_SYSTEM
from pipeline.hunt.retry_policy import OUTCOME_INVALID
from pipeline.hunt.tools import TOOL_NAMES, HuntToolbox, ToolResult

SINK_SEARCH = "sink_search"
SOURCE_TRACE = "source_trace"
SANITIZER_CHECK = "sanitizer_check"
AUTHZ_CHECK = "authz_check"
CONFIG_CHECK = "config_check"
STRATEGIES = (SINK_SEARCH, SOURCE_TRACE, SANITIZER_CHECK, AUTHZ_CHECK, CONFIG_CHECK)

OUTCOME_INSUFFICIENT = "INSUFFICIENT_EVIDENCE"

DEFAULT_MAX_STEPS = 12
# With this many steps left only report/abandon are accepted, and the step
# limit itself ends in one forced verdict turn: an investigation always
# concludes instead of burning its budget circling evidence it already has.
FINAL_STEPS = 2
# Non-conclusion actions allowed once every checklist item is established.
STEPS_AFTER_EVIDENCE_COMPLETE = 2
# Fraction of the per-hypothesis USD share after which it must conclude.
SPEND_SHARE_CONCLUDE_AT = 0.8
MAX_REFORMULATIONS_PER_INTENT = 3
MAX_CONSECUTIVE_SATISFIED_SEARCHES = 3
MAX_REPORT_REFUSALS = 2
RECENT_RESULTS_VERBATIM = 4
RESULT_TEXT_CAP = 6000
USER_PROMPT_CHAR_CAP = 48_000
TURN_MAX_TOKENS = 1500

SEARCH_TOOLS = frozenset({"search", "search_sinks", "search_sources", "list_files"})
TOOL_STRATEGY = {
    "search_sinks": SINK_SEARCH,
    "search_sources": SOURCE_TRACE,
    "callers": SOURCE_TRACE,
    "find_sanitizers": SANITIZER_CHECK,
    "find_authz": AUTHZ_CHECK,
}
STATE_CHANGING_ENDPOINTS = r"@(?:Post|Put|Delete|Patch)Mapping\b|@(?:POST|PUT|DELETE|PATCH)\b"

STATUS_REPORTED = "reported"
STATUS_REFUTED = "refuted"
STATUS_INCONCLUSIVE = "inconclusive"
STATUS_BUDGET = "budget"
STATUS_ERROR = "error"


def _loc(raw: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, dict):
        return None
    file = str(raw.get("file") or "").strip()
    try:
        line = int(raw.get("line"))
    except (TypeError, ValueError):
        return None
    if not file or line <= 0:
        return None
    return {"file": file, "line": line, "expr": str(raw.get("expr") or raw.get("method") or "")[:300],
            **({"method": str(raw["method"])[:200]} if raw.get("method") else {}),
            **({"role": str(raw["role"])} if raw.get("role") else {})}


@dataclass
class Checklist:
    sink: Optional[Dict[str, Any]] = None
    source: Optional[Dict[str, Any]] = None
    path: List[Dict[str, Any]] = field(default_factory=list)
    sanitizers_checked: bool = False
    authz_checked: bool = False

    def render(self, hypothesis: Hypothesis) -> str:
        def mark(ok: bool) -> str:
            return "[x]" if ok else "[ ]"

        rows = [f"{mark(bool(self.sink))} sink: " + (f"{self.sink['file']}:{self.sink['line']}" if self.sink else "not located")]
        if hypothesis.needs_source and not hypothesis.access_control:
            rows.append(f"{mark(bool(self.source))} source: " + (f"{self.source['file']}:{self.source['line']}" if self.source else "not located"))
            rows.append(f"{mark(bool(self.path) or self._same_file())} path: " + (
                " -> ".join(f"{p['file'].rsplit('/', 1)[-1]}:{p['line']}" for p in self.path) or ("same file" if self._same_file() else "not traced")
            ))
            rows.append(f"{mark(self.sanitizers_checked)} sanitizers checked")
        if hypothesis.access_control:
            rows.append(f"{mark(self.authz_checked)} authorization checked")
        return "\n".join(rows)

    def _same_file(self) -> bool:
        return bool(self.sink and self.source and self.sink["file"] == self.source["file"])


def missing_items(
    hypothesis: Hypothesis,
    *,
    sink: Optional[Dict[str, Any]],
    source: Optional[Dict[str, Any]],
    path: List[Dict[str, Any]],
    sanitizers_checked: bool,
    authz_checked: bool,
    ledger: EvidenceLedger,
) -> List[str]:
    """What a report on this hypothesis still lacks, most fundamental first."""
    missing: List[str] = []
    if sink is None or not ledger.covers(sink["file"], sink["line"], slack=2):
        missing.append("sink: the vulnerable line has not been shown by a tool (search or read it)")
        return missing
    if hypothesis.sink_kind in CONFIG_KINDS:
        return missing
    if hypothesis.access_control:
        if not authz_checked:
            missing.append("authorization: call find_authz on the endpoint to check annotations and security rules")
        return missing
    if source is None or not ledger.covers(source["file"], source["line"], slack=2):
        missing.append("source: where untrusted input enters has not been located (trace callers / entry-point parameters)")
        return missing
    if source["file"] != sink["file"]:
        if not path:
            missing.append("path: the calls connecting the source file to the sink file have not been traced")
        else:
            unobserved = [p for p in path if not ledger.covers(p["file"], p["line"], slack=2)]
            if unobserved:
                missing.append("path: hop(s) " + ", ".join(f"{p['file']}:{p['line']}" for p in unobserved[:3])
                               + " not shown by any tool")
    if not sanitizers_checked:
        missing.append("sanitizers: check for encoding/validation/parameter binding between source and sink (find_sanitizers or read the code between them)")
    return missing


_GAP_ORDER = ("sink", "source", "path", "sanitizers", "authorization")


def _gap_rank(item: str) -> int:
    head = item.split(":", 1)[0]
    return _GAP_ORDER.index(head) if head in _GAP_ORDER else len(_GAP_ORDER)


def strategy_for_missing(item: str, hypothesis: Hypothesis) -> str:
    head = item.split(":", 1)[0]
    if head == "sink":
        return CONFIG_CHECK if hypothesis.sink_kind in CONFIG_KINDS else SINK_SEARCH
    if head in ("source", "path"):
        return SOURCE_TRACE
    if head == "sanitizers":
        return SANITIZER_CHECK
    if head == "authorization":
        return AUTHZ_CHECK
    return SOURCE_TRACE


@dataclass
class InvestigationResult:
    hypothesis: Hypothesis
    status: str
    candidates: List[Dict[str, Any]] = field(default_factory=list)
    refuted: List[Dict[str, Any]] = field(default_factory=list)
    steps: int = 0
    llm_turns: int = 0
    searches: List[Dict[str, Any]] = field(default_factory=list)
    strategy_trail: List[str] = field(default_factory=list)
    insufficient_evidence: int = 0
    blocked_actions: int = 0
    reason: str = ""
    ledger: EvidenceLedger = field(default_factory=EvidenceLedger)
    checklist: Checklist = field(default_factory=Checklist)


@dataclass
class _Turn:
    step: int
    action: str
    result: str
    summary: str


class Investigator:
    def __init__(
        self,
        hypothesis: Hypothesis,
        *,
        toolbox: HuntToolbox,
        llm: Callable[..., str],
        dossier_excerpt: str = "",
        max_steps: int = DEFAULT_MAX_STEPS,
        on_event: Optional[Callable[[str], None]] = None,
        spend_cap_usd: Optional[float] = None,
    ) -> None:
        self.h = hypothesis
        self.spend_cap_usd = spend_cap_usd
        self._steps_since_complete = 0
        self.toolbox = toolbox
        self.ledger = toolbox.ledger
        self.llm = llm
        self.dossier_excerpt = dossier_excerpt
        self.max_steps = max_steps
        self.on_event = on_event or (lambda _msg: None)
        self.checklist = Checklist()
        self.turns: List[_Turn] = []
        self.result = InvestigationResult(hypothesis=hypothesis, status=STATUS_INCONCLUSIVE, ledger=self.ledger,
                                          checklist=self.checklist)
        self._memo: Dict[str, str] = {}
        self._intent_counts: Dict[str, int] = {}
        self._consecutive: Tuple[Optional[str], int] = (None, 0)
        self._blocked: set = set()
        self._report_refusals = 0
        self._feedback: List[str] = []
        self._sink_tokens = self._kind_tokens(hypothesis.sink_kind)
        self._final = False

    # -- public ------------------------------------------------------------

    def run(self) -> InvestigationResult:
        try:
            self._prerun()
            while self.result.steps < self.max_steps:
                action = self._next_action(final=self._must_conclude())
                if action is None:
                    return self.result
                if self._execute(action):
                    return self.result
            # Out of steps: one forced verdict turn rather than discarding
            # everything the investigation established.
            action = self._next_action(final=True)
            if action is not None and self._execute(action):
                return self.result
            self.result.status = STATUS_INCONCLUSIVE
            self.result.reason = self.result.reason or f"step limit ({self.max_steps}) reached without a verdict"
            return self.result
        except HuntBudgetExceeded as exc:
            self.result.status = STATUS_BUDGET
            self.result.reason = f"hunt budget exhausted ({exc})"
            return self.result

    def _spent(self) -> float:
        return float(getattr(self.llm, "spent_usd", 0.0) or 0.0)

    def _must_conclude(self) -> bool:
        if self.max_steps - self.result.steps <= FINAL_STEPS:
            return True
        if self.spend_cap_usd is not None and self._spent() >= self.spend_cap_usd * SPEND_SHARE_CONCLUDE_AT:
            return True
        return not self.current_missing() and self._steps_since_complete >= STEPS_AFTER_EVIDENCE_COMPLETE

    # -- engine-run first steps ----------------------------------------------

    def _prerun(self) -> None:
        """Run the obvious first searches without spending an LLM turn."""
        kind = self.h.sink_kind
        hops = (self.h.flow or {}).get("hops") or []
        if hops:
            # Show the flow's two ends; the model reads the middle hops itself.
            for hop in ([hops[0], hops[-1]] if len(hops) > 1 else hops):
                start = max(1, int(hop.get("line") or 1) - 8)
                self._record(self.toolbox.run("read", {"file": hop.get("file"), "start": start, "end": start + 20}),
                             f"engine: read flow {hop.get('role') or 'hop'}")
            # Static analysis already located both ends and the engine just
            # showed them, so they start out established: the investigation
            # begins at "does the value really flow, and is it sanitized".
            ends = [_loc({"file": h.get("file"), "line": h.get("line"), "expr": h.get("label")})
                    for h in (hops[0], hops[-1])]
            if all(ends) and all(self.ledger.covers(e["file"], e["line"]) for e in ends):
                self.checklist.source, self.checklist.sink = ends[0], ends[1]
                self.checklist.path = [p for p in (
                    _loc({"file": h.get("file"), "line": h.get("line"), "method": h.get("name")}) for h in hops[1:-1]
                ) if p]
            return
        if self.h.access_control:
            res = self.toolbox._search("search", STATE_CHANGING_ENDPOINTS, intent="state-changing endpoints",
                                       trusted=True)
            self._record(res, "engine: list state-changing endpoints")
            return
        if kind in catalog.sink_patterns():
            self._record(self.toolbox.run("search_sinks", {"kind": kind, "intent": f"{kind} sinks"}),
                         f"engine: search_sinks {kind}")
        if self.h.initial_strategy == STRATEGY_SOURCE_FIRST and not self.h.access_control:
            self._record(self.toolbox.run("search_sources", {}), "engine: search_sources")

    # -- the loop --------------------------------------------------------------

    def _next_action(self, *, final: bool = False) -> Optional[Dict[str, Any]]:
        user = self._build_user_prompt()
        allowed = ("report", "abandon") if final else TOOL_NAMES + ("report", "abandon")
        if final:
            self._final = True
            user += (
                "\n\nFINAL TURN: no more tools. Decide now from what you have seen. Reply with action "
                '"report" (each finding with the sink, and the source/path you established; '
                "gaps lower its confidence but do not stop you reporting it) or \"abandon\" with "
                'verdict "refuted" (you saw why it is safe) or "inconclusive".'
            )
        for attempt in range(2):
            prompt = user if attempt == 0 else (
                user + "\n\nYour previous reply was not a valid action. Reply with ONE JSON object "
                "with keys thought, strategy, action, args (and optional evidence) — no prose."
                + (' The action must be "report" or "abandon".' if final else "")
            )
            raw = self.llm(HUNT_SYSTEM, prompt, max_tokens=TURN_MAX_TOKENS, step="hunt_investigate")
            self.result.llm_turns += 1
            data, err = parse_llm_json_dict(raw)
            action = str((data or {}).get("action") or "").strip()
            if not err and action in allowed:
                args = data.get("args")
                data["args"] = args if isinstance(args, dict) else {}
                return data
        self.result.status = STATUS_INCONCLUSIVE
        self.result.reason = "model did not return a valid " + ("verdict" if final else "action")
        return None

    def _execute(self, data: Dict[str, Any]) -> bool:
        self.result.steps += 1
        action = data["action"]
        args = data["args"]
        self._apply_evidence_notes(data.get("evidence"))
        declared = str(data.get("strategy") or "").strip()
        strategy = self._effective_strategy(action, args, declared)
        self.result.strategy_trail.append(strategy)
        thought = str(data.get("thought") or "")[:200]
        if action not in ("report", "abandon") and not self.current_missing():
            self._steps_since_complete += 1

        if action == "abandon":
            verdict = str(args.get("verdict") or "").strip().lower()
            self.result.status = STATUS_REFUTED if verdict == "refuted" else STATUS_INCONCLUSIVE
            self.result.reason = str(args.get("reason") or thought)[:300]
            self.on_event(f"{self.h.id}: abandon ({self.result.status}) — {self.result.reason}")
            return True
        if action == "report":
            return self._handle_report(args)

        blocked = self._block_reason(action, args, strategy)
        if blocked:
            self.result.blocked_actions += 1
            self.result.insufficient_evidence += 1
            self._turn(action, args, f"{OUTCOME_INSUFFICIENT}: {blocked}", f"{action} -> BLOCKED")
            self.on_event(f"{self.h.id}: blocked {action} ({OUTCOME_INSUFFICIENT})")
            return False

        memo_key = self._memo_key(action, args)
        if memo_key in self._memo:
            self._turn(action, args, f"Already run: {self._memo[memo_key]}. Do not repeat a search; change the "
                                     "pattern, the glob, or the strategy.", f"{action} -> REPEAT")
            return False
        intent = self._intent_key(action, args)
        if intent:
            count = self._intent_counts.get(intent, 0) + 1
            self._intent_counts[intent] = count
            if count > MAX_REFORMULATIONS_PER_INTENT:
                self._turn(action, args, f"Intent '{intent}' has had {MAX_REFORMULATIONS_PER_INTENT} searches already. "
                                         "Stop reformulating it: read what you found, switch strategy, or report/abandon.",
                           f"{action} -> INTENT EXHAUSTED")
                return False

        result = self.toolbox.run(action, args)
        self._memo[memo_key] = result.summary
        self._record(result, None)
        self._update_checklist_from_tool(action, args, result)
        self._track_consecutive(action, strategy)
        self.on_event(f"{self.h.id}: {result.summary}")
        return False

    # -- report handling ---------------------------------------------------------

    def _handle_report(self, args: Dict[str, Any]) -> bool:
        raw_findings = args.get("findings")
        if isinstance(raw_findings, dict):
            raw_findings = [raw_findings]
        findings = [f for f in (raw_findings or []) if isinstance(f, dict)]
        if not findings:
            self._turn("report", args, "error: report needs {\"findings\": [...]} with at least one finding, "
                                       "or use abandon.", "report -> EMPTY")
            return False
        gaps_by_index: List[List[str]] = []
        for f in findings:
            if str(f.get("verdict") or "").lower().startswith("false"):
                gaps_by_index.append([])
                continue
            sink = _loc(f.get("sink")) or self.checklist.sink
            source = _loc(f.get("source")) or self.checklist.source
            path = [p for p in (_loc(p) for p in (f.get("path") or [])) if p] or self.checklist.path
            gaps_by_index.append(missing_items(
                self.h, sink=sink, source=source, path=path,
                sanitizers_checked=self.checklist.sanitizers_checked or self._read_between(source, sink),
                authz_checked=self.checklist.authz_checked, ledger=self.ledger,
            ))
        gaps = sorted({g for gs in gaps_by_index for g in gs}, key=_gap_rank)
        # A final-turn report is accepted with its gaps; the validator caps
        # such a finding at unverified rather than losing it.
        if gaps and self._report_refusals < MAX_REPORT_REFUSALS and not self._final:
            self._report_refusals += 1
            self.result.insufficient_evidence += 1
            next_strategy = strategy_for_missing(gaps[0], self.h)
            if self.checklist.sink:
                self._blocked.add(SINK_SEARCH)
            self._turn("report", {"findings": len(findings)},
                       f"{OUTCOME_INSUFFICIENT}: the report was not accepted. Missing:\n- " + "\n- ".join(gaps)
                       + f"\nSwitch to strategy '{next_strategy}'."
                       + (" Further sink searches are blocked: the sink is already located." if SINK_SEARCH in self._blocked else ""),
                       f"report -> {OUTCOME_INSUFFICIENT}")
            self.on_event(f"{self.h.id}: report refused ({OUTCOME_INSUFFICIENT}); next: {next_strategy}")
            return False
        for f, gaps_for in zip(findings, gaps_by_index):
            candidate = dict(f)
            candidate["_evidence_gaps"] = gaps_for
            candidate["_hypothesis"] = {"id": self.h.id, "cwe": self.h.cwe, "vuln_class": self.h.vuln_class,
                                        "sink_kind": self.h.sink_kind, "needs_source": self.h.needs_source,
                                        "access_control": self.h.access_control}
            if str(f.get("verdict") or "").lower().startswith("false"):
                self.result.refuted.append(candidate)
            else:
                self.result.candidates.append(candidate)
        self.result.status = STATUS_REPORTED if self.result.candidates else STATUS_REFUTED
        self.result.reason = f"{len(self.result.candidates)} candidate(s) reported"
        self.on_event(f"{self.h.id}: reported {len(self.result.candidates)} candidate(s)")
        return True

    def _read_between(self, source: Optional[Dict[str, Any]], sink: Optional[Dict[str, Any]]) -> bool:
        """The model saw every line between source and sink (same file)."""
        if not source or not sink or source["file"] != sink["file"]:
            return False
        lo, hi = sorted((source["line"], sink["line"]))
        return all(self.ledger.covers(sink["file"], ln) for ln in range(lo, hi + 1))

    # -- checklist ---------------------------------------------------------------

    def _apply_evidence_notes(self, evidence: Any) -> None:
        if not isinstance(evidence, dict):
            return
        ignored = []
        for key in ("sink", "source"):
            loc = _loc(evidence.get(key))
            if loc is None:
                continue
            if self.ledger.covers(loc["file"], loc["line"], slack=2):
                setattr(self.checklist, key, loc)
            else:
                ignored.append(f"{key} {loc['file']}:{loc['line']}")
        hops = [p for p in (_loc(p) for p in (evidence.get("path") or [])) if p]
        if hops:
            observed = [p for p in hops if self.ledger.covers(p["file"], p["line"], slack=2)]
            ignored += [f"hop {p['file']}:{p['line']}" for p in hops if p not in observed]
            if observed:
                self.checklist.path = observed
        if ignored:
            self._feedback.append(
                "Evidence notes ignored (no tool has shown you these lines yet): " + ", ".join(ignored[:4])
            )
        if self._read_between(self.checklist.source, self.checklist.sink):
            self.checklist.sanitizers_checked = True

    def _update_checklist_from_tool(self, action: str, args: Dict[str, Any], result: ToolResult) -> None:
        if not result.ok:
            return
        if action == "find_sanitizers":
            self.checklist.sanitizers_checked = True
        elif action == "find_authz":
            self.checklist.authz_checked = True

    def _satisfied(self, strategy: str) -> bool:
        c = self.checklist
        if strategy in (SINK_SEARCH, CONFIG_CHECK):
            return c.sink is not None
        if strategy == SOURCE_TRACE:
            return c.source is not None and (bool(c.path) or c._same_file())
        if strategy == SANITIZER_CHECK:
            return c.sanitizers_checked
        if strategy == AUTHZ_CHECK:
            return c.authz_checked
        return False

    def current_missing(self) -> List[str]:
        return missing_items(
            self.h, sink=self.checklist.sink, source=self.checklist.source, path=self.checklist.path,
            sanitizers_checked=self.checklist.sanitizers_checked, authz_checked=self.checklist.authz_checked,
            ledger=self.ledger,
        )

    def current_strategy(self) -> str:
        missing = self.current_missing()
        if missing:
            return strategy_for_missing(missing[0], self.h)
        return "report"

    # -- guards ------------------------------------------------------------------

    def _effective_strategy(self, action: str, args: Dict[str, Any], declared: str) -> str:
        if action in TOOL_STRATEGY:
            return TOOL_STRATEGY[action]
        if action == "search" and self._looks_like_sink_search(str(args.get("pattern") or "")):
            return SINK_SEARCH
        if declared in STRATEGIES:
            return declared
        current = self.current_strategy()
        return current if current in STRATEGIES else SINK_SEARCH

    def _block_reason(self, action: str, args: Dict[str, Any], strategy: str) -> Optional[str]:
        if action not in SEARCH_TOOLS:
            return None
        next_strategy = self.current_strategy()
        if strategy in self._blocked and self._satisfied(strategy):
            return (f"{strategy.replace('_', ' ')} is already established and further searches for it are "
                    f"blocked. Next: '{next_strategy}' — " + "; ".join(self.current_missing()[:2]))
        last, count = self._consecutive
        if last == strategy and count >= MAX_CONSECUTIVE_SATISFIED_SEARCHES and self._satisfied(strategy):
            self._blocked.add(strategy)
            return (f"{count} consecutive {strategy.replace('_', ' ')} searches after it was already established. "
                    f"Next: '{next_strategy}' — " + "; ".join(self.current_missing()[:2]))
        return None

    def _track_consecutive(self, action: str, strategy: str) -> None:
        if action not in SEARCH_TOOLS:
            return
        last, count = self._consecutive
        self._consecutive = (strategy, count + 1 if last == strategy else 1)

    def _looks_like_sink_search(self, pattern: str) -> bool:
        return any(tok in pattern for tok in self._sink_tokens)

    @staticmethod
    def _kind_tokens(kind: str) -> List[str]:
        tokens = set()
        for p in catalog.sink_patterns().get(kind, []):
            tokens.update(t for t in re.findall(r"[A-Za-z]{6,}", p) if t not in ("getInstance",))
        return sorted(tokens)

    @staticmethod
    def _memo_key(action: str, args: Dict[str, Any]) -> str:
        norm = {k: (" ".join(str(v).split()) if isinstance(v, str) else v) for k, v in sorted(args.items()) if k != "intent"}
        return action + json.dumps(norm, sort_keys=True, default=str)

    @staticmethod
    def _intent_key(action: str, args: Dict[str, Any]) -> Optional[str]:
        if action != "search":
            return None
        intent = " ".join(str(args.get("intent") or "").lower().split())
        return intent or None

    # -- transcript ---------------------------------------------------------------

    def _record(self, result: ToolResult, label: Optional[str]) -> None:
        if result.tool in SEARCH_TOOLS or result.tool == "find_sanitizers":
            self.result.searches.append({
                "tool": result.tool, "summary": result.summary, "outcome": result.outcome,
                "pattern": result.data.get("pattern"), "kept": result.data.get("kept_matches"),
                # Model-written patterns only (engine seeds are trusted
                # catalog text), with what they surfaced: learned.py's input.
                "model_written": label is None and result.tool == "search",
                "relaxed_pattern": result.data.get("relaxed_pattern"),
                "shown": list(result.data.get("shown") or [])[:60],
            })
        self.turns.append(_Turn(len(self.turns) + 1, label or result.tool, result.text[:RESULT_TEXT_CAP], result.summary))

    def _turn(self, action: str, args: Any, text: str, summary: str) -> None:
        self.turns.append(_Turn(len(self.turns) + 1, f"{action} {json.dumps(args, default=str)[:200]}", text, summary))

    def _build_user_prompt(self) -> str:
        parts = [self.h.describe()]
        if self.dossier_excerpt:
            parts.append("Repository context:\n" + self.dossier_excerpt)
        parts.append("Evidence established so far (verified against what tools showed you):\n" + self.checklist.render(self.h))
        missing = self.current_missing()
        parts.append(
            f"Current strategy: {self.current_strategy()}"
            + (f" — still missing: {missing[0]}" if missing else " — evidence complete; report or abandon")
        )
        left = self.max_steps - self.result.steps
        parts.append(
            f"Steps used: {self.result.steps} of {self.max_steps}. With {FINAL_STEPS} left only report/abandon "
            f"are accepted, so plan to reach a verdict within {max(0, left - FINAL_STEPS)} more tool call(s)."
            + (" Evidence is complete: report (or abandon as refuted) now." if not self.current_missing() else "")
        )
        tail: List[str] = []
        if self._feedback:
            tail.append("Engine feedback:\n" + "\n".join(self._feedback[-3:]))
            self._feedback = []
        tail.append("Reply with your next JSON action.")
        # History sits between the state and the feedback, shrinking the
        # verbatim window until the prompt fits: older results always
        # survive as one-line summaries.
        for verbatim in range(RECENT_RESULTS_VERBATIM, -1, -1):
            history = self._render_history(verbatim)
            text = "\n\n".join(parts + ([history] if history else []) + tail)
            if len(text) <= USER_PROMPT_CHAR_CAP:
                return text
        return text[:USER_PROMPT_CHAR_CAP]

    def _render_history(self, verbatim: int) -> str:
        older = self.turns[:-verbatim] if verbatim else self.turns
        recent = self.turns[-verbatim:] if verbatim else []
        out = []
        if older:
            out.append("Earlier steps (summarized):\n" + "\n".join(f"{t.step}. {t.summary}" for t in older))
        if recent:
            out.append("Recent results:\n" + "\n\n".join(f"[{t.step}] {t.action}\n{t.result}" for t in recent))
        return "\n\n".join(out)
