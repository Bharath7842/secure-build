"""Orchestrates one agentic hunt: dossier -> plan -> parallel investigations
-> validation -> findings. Called by sast_scan_agent.node_hunt_security.

Investigations run on a small thread pool (each with its own toolbox and
evidence ledger); validation runs on the calling thread as each one
finishes, so the finding-level dedupe index and the findings writer are only
ever touched from one place.
"""

from __future__ import annotations

import concurrent.futures
import queue
import threading
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from llm_client import call_llm
from pipeline.hunt.budget import BudgetLimits, HuntBudget
from pipeline.hunt.evidence import EvidenceLedger
from pipeline.hunt.learned import candidates_from_investigations, evaluate_candidates
from pipeline.hunt.investigator import (
    DEFAULT_MAX_STEPS,
    STATUS_BUDGET,
    STATUS_REPORTED,
    InvestigationResult,
    Investigator,
)
from pipeline.hunt.llm import BudgetedLlm
from pipeline.hunt.planner import DEFAULT_MAX_HYPOTHESES, plan_hypotheses, seed_hypotheses
from pipeline.hunt.redact import redact
from pipeline.hunt.repo_index import build_dossier
from pipeline.hunt.rg_runner import RgRunner
from pipeline.hunt.symbols import SymbolService, build_lazy_graph_builder
from pipeline.hunt.tools import POLICY_DEPRIORITIZE, POLICY_EXCLUDE, POLICY_INCLUDE, HuntToolbox
from pipeline.hunt.validator import (
    STATUS_CORROBORATED,
    STATUS_HALLUCINATED,
    STATUS_PUBLISHED,
    STATUS_SUPPRESSED,
    ExistingFindings,
    Validator,
)

PROFILE_DEFAULT = "default"
# Benchmarks (OWASP Benchmark, Juliet) keep their test cases under test-like
# and generated-looking paths; filtering those would score as misses.
PROFILE_BENCHMARK = "benchmark"
DEFAULT_WORKERS = 4


@dataclass
class HuntOptions:
    max_hypotheses: int = DEFAULT_MAX_HYPOTHESES
    max_steps: int = DEFAULT_MAX_STEPS
    workers: int = DEFAULT_WORKERS
    max_usd: Optional[float] = None  # None: share of the scan's remaining cutoff
    max_tokens: Optional[int] = BudgetLimits.max_tokens
    max_wall_seconds: Optional[float] = BudgetLimits.max_wall_seconds
    max_llm_calls: Optional[int] = BudgetLimits.max_llm_calls
    max_rg_calls: Optional[int] = BudgetLimits.max_rg_calls
    test_paths: str = POLICY_DEPRIORITIZE
    generated_paths: str = POLICY_EXCLUDE
    profile: str = PROFILE_DEFAULT
    suppress_no_cwe: bool = True
    suppress_http_findings: bool = False
    suppress_low_confidence_false_positives: bool = False

    def __post_init__(self) -> None:
        if self.profile == PROFILE_BENCHMARK:
            self.test_paths = POLICY_INCLUDE
            self.generated_paths = POLICY_INCLUDE


def _empty_results(reason: str) -> Dict[str, Any]:
    return {
        "files_scanned": 0, "files": [], "tp_count": 0, "fp_count": 0, "unverified_count": 0,
        "hypotheses": [], "skipped_reason": reason,
    }


def run_hunt(
    *,
    root: Path | str,
    inventory: Sequence[str],
    seed_entries: Sequence[Dict[str, Any]],
    stack: str,
    frameworks: Sequence[str] = (),
    surfaces: Sequence[Any] = (),
    catalog_hits: Optional[Dict[str, int]] = None,
    flow_candidates: Sequence[Dict[str, Any]] = (),
    graph: Any = None,
    java_paths: Sequence[str] = (),
    existing_file_results: Sequence[Dict[str, Any]] = (),
    usage: Optional[Dict[str, Any]] = None,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    call_llm_fn: Callable[..., str] = call_llm,
    findings_writer: Optional[Callable[[str, List[Dict[str, Any]]], None]] = None,
    options: Optional[HuntOptions] = None,
    on_event: Callable[[str], None] = lambda _msg: None,
    rg_binary: Optional[str] = None,
) -> Dict[str, Any]:
    options = options or HuntOptions()
    root = Path(root)
    runner = RgRunner(root, binary=rg_binary, allowed_files=inventory)
    if not runner.available():
        return _empty_results("ripgrep (rg) is not installed")

    budget = HuntBudget(
        BudgetLimits.for_scan(
            usage, max_usd=options.max_usd, max_tokens=options.max_tokens,
            max_wall_seconds=options.max_wall_seconds, max_llm_calls=options.max_llm_calls,
            max_rg_calls=options.max_rg_calls,
        ),
        provider=(usage or {}).get("active_provider") or llm_provider,
        model=(usage or {}).get("active_model") or llm_model,
    )
    llm = BudgetedLlm(budget=budget, usage=usage, provider=llm_provider, model=llm_model, call_llm_fn=call_llm_fn)
    symbols = SymbolService(
        root, runner, graph=graph,
        graph_builder=build_lazy_graph_builder(root, java_paths) if graph is None and java_paths else None,
        joern_flows=flow_candidates,
    )
    risk_by_path = {e["path"]: str(e.get("risk_level") or "") for e in seed_entries if e.get("path")}

    dossier = build_dossier(
        runner=runner, symbols=symbols, stack=stack, frameworks=frameworks, surfaces=surfaces,
        seed_entries=seed_entries, inventory=inventory, catalog_hits=catalog_hits,
        flow_candidates=[f for f in flow_candidates if f.get("entry_tier") != "joern"],
    )
    on_event(
        f"Dossier: {len(inventory)} file(s), {dossier.entry_point_count} entry point(s), "
        f"sink kinds present: {', '.join(dossier.sink_kinds_present()) or 'none'}"
        + ("; call graph available" if dossier.has_call_graph else "; no call graph (textual navigation only)")
    )

    seeds = seed_hypotheses(dossier, flow_candidates=[f for f in flow_candidates if f.get("hops")])
    plan = plan_hypotheses(dossier, seeds, llm=llm, max_hypotheses=options.max_hypotheses)
    hypotheses = plan["hypotheses"]
    on_event(
        f"Planned {len(hypotheses)} hypothesis(es)"
        + (f" (planner unavailable: {plan['planner_error']}; using dossier seeds)" if plan["planner_error"] else "")
        + ": " + ", ".join(f"{h.id} {h.vuln_class}" for h in hypotheses[:8])
        + (" ..." if len(hypotheses) > 8 else "")
    )

    dossier_excerpt = redact(dossier.render(max_chars=4000))
    existing = ExistingFindings.from_file_results(existing_file_results)
    validation_toolbox = HuntToolbox(
        root=root, runner=runner, symbols=symbols, ledger=EvidenceLedger(), risk_by_path=risk_by_path,
        inventory=inventory, test_policy=options.test_paths, generated_policy=options.generated_paths,
    )
    validator = Validator(
        toolbox=validation_toolbox, symbols=symbols, existing=existing, llm=llm, stack_context=stack,
        suppress_no_cwe=options.suppress_no_cwe, suppress_http_findings=options.suppress_http_findings,
        suppress_low_confidence_false_positives=options.suppress_low_confidence_false_positives,
    )
    # Narration from investigator threads is queued and printed by the
    # calling thread: the API's log capture is per-thread, so lines printed on
    # a worker thread never reached the scan log.
    events: "queue.Queue[str]" = queue.Queue()
    caller = threading.get_ident()

    def _event(msg: str) -> None:
        if threading.get_ident() == caller:
            on_event(msg)
        else:
            events.put(msg)

    def _drain_events() -> None:
        while True:
            try:
                on_event(events.get_nowait())
            except queue.Empty:
                return

    start_lock = threading.Lock()
    not_started = [len(hypotheses)]

    def _spend_share() -> Optional[float]:
        """An equal share of what is left among the hypotheses not yet
        started, so early investigations can't starve later ones."""
        with start_lock:
            remaining = budget.remaining_usd()
            share = None if remaining is None else remaining / max(1, not_started[0])
            not_started[0] -= 1
            return share

    def _investigate(index: int, hypothesis) -> InvestigationResult:
        share = _spend_share()
        _event(f"Hunting hypothesis {index}/{len(hypotheses)}: {hypothesis.cwe} {hypothesis.vuln_class}"
               + (f" (budget share ${share:.3f})" if share is not None else ""))
        toolbox = HuntToolbox(
            root=root, runner=runner, symbols=symbols, ledger=EvidenceLedger(), risk_by_path=risk_by_path,
            inventory=inventory, test_policy=options.test_paths, generated_policy=options.generated_paths,
            rg_gate=budget.reserve_rg,
        )
        result = Investigator(
            hypothesis, toolbox=toolbox, llm=llm.for_investigation(), dossier_excerpt=dossier_excerpt,
            max_steps=options.max_steps, on_event=_event, spend_cap_usd=share,
        ).run()
        _event(f"{hypothesis.id}: {result.status}" + (f" — {result.reason}" if result.reason else ""))
        return result

    files: Dict[str, Dict[str, Any]] = {}
    hypothesis_rows: List[Dict[str, Any]] = []
    # For learned-rule promotion: what each investigation searched, what it
    # confirmed, and which sites were refuted or disputed (negatives).
    searches_by_hypothesis: Dict[str, List[Dict[str, Any]]] = {}
    confirmed: List[Dict[str, Any]] = []
    negatives: List[tuple] = []
    tallies: Counter = Counter()
    levels: Counter = Counter()

    def _absorb(result: InvestigationResult) -> None:
        row_status = result.status
        published = corroborated = dropped = 0
        searches_by_hypothesis[result.hypothesis.id] = list(result.searches)
        for refuted in result.refuted:
            sink = refuted.get("sink") if isinstance(refuted.get("sink"), dict) else None
            if sink and sink.get("file") and sink.get("line"):
                negatives.append((str(sink["file"]), int(sink["line"])))
        for candidate in result.candidates:
            outcome = validator.validate(candidate, result.ledger)
            tallies[outcome.status] += 1
            if outcome.evidence_level:
                levels[outcome.evidence_level] += 1
            if outcome.status == STATUS_PUBLISHED and outcome.finding is not None:
                f = outcome.finding
                published += 1
                bucket = files.setdefault(f["file_path"], {
                    "file_path": f["file_path"], "findings": [], "chunk_errors": [],
                })
                bucket["findings"].append(f)
                if findings_writer is not None:
                    findings_writer(f["file_path"], [f])
                if f["verdict"] == "true_positive":
                    confirmed.append({"file_path": f["file_path"], "line": f["line"], "cwe": f.get("cwe"),
                                      "title": f.get("title"), "hypothesis_id": result.hypothesis.id})
                elif outcome.verifier == "disagree":
                    negatives.append((f["file_path"], int(f["line"])))
                _event(
                    f"{result.hypothesis.id}: published {f['verdict']} {f.get('cwe')} at "
                    f"{f['file_path']}:{f['line']} [evidence {outcome.evidence_level}, verifier {outcome.verifier}]"
                )
            elif outcome.status == STATUS_CORROBORATED:
                corroborated += 1
                _event(f"{result.hypothesis.id}: corroborates existing finding {outcome.corroborates}")
            else:
                dropped += 1
                _event(f"{result.hypothesis.id}: candidate {outcome.status} — {'; '.join(outcome.reasons)[:200]}")
        if row_status == STATUS_REPORTED:
            row_status = "confirmed" if published or corroborated else "refuted"
        hypothesis_rows.append({
            "id": result.hypothesis.id, "cwe": result.hypothesis.cwe,
            "vuln_class": result.hypothesis.vuln_class, "sink_kind": result.hypothesis.sink_kind,
            "origin": result.hypothesis.origin, "status": row_status, "reason": result.reason,
            "steps": result.steps, "llm_turns": result.llm_turns,
            "strategy_trail": _collapse(result.strategy_trail),
            "searches": [{k: v for k, v in s.items() if k != "shown"} for s in result.searches[-20:]],
            "insufficient_evidence": result.insufficient_evidence,
            "blocked_actions": result.blocked_actions,
            "candidates": len(result.candidates), "published": published,
            "corroborated": corroborated, "dropped": dropped, "refuted_candidates": len(result.refuted),
            "evidence": result.ledger.summary(),
        })

    workers = max(1, int(options.workers))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_investigate, i, h): h for i, h in enumerate(hypotheses, start=1)}
        pending = set(futures)
        while pending:
            done, pending = concurrent.futures.wait(
                pending, timeout=0.5, return_when=concurrent.futures.FIRST_COMPLETED,
            )
            _drain_events()
            for future in done:
                try:
                    result = future.result()
                except Exception as exc:  # noqa: BLE001 — one hypothesis must not kill the hunt
                    h = futures[future]
                    hypothesis_rows.append({"id": h.id, "cwe": h.cwe, "vuln_class": h.vuln_class,
                                            "status": "error", "reason": f"{type(exc).__name__}: {exc}"})
                    continue
                _absorb(result)
    _drain_events()

    learned_rules = evaluate_candidates(
        candidates_from_investigations(searches_by_hypothesis, confirmed),
        negatives=negatives, runner=runner, read_lines=validation_toolbox._lines,
    ) if confirmed else []
    for row in learned_rules:
        _event(f"Learned pattern /{row['pattern'][:80]}/: {row['status']}"
               + (f" — {'; '.join(row['reasons'])}" if row["reasons"] else ""))

    file_results = list(files.values())
    for r in file_results:
        fs = r["findings"]
        r["tp_count"] = sum(1 for f in fs if f.get("verdict") == "true_positive")
        r["fp_count"] = sum(1 for f in fs if f.get("verdict") == "false_positive")
        r["unverified_count"] = sum(1 for f in fs if f.get("verdict") == "unverified")
    order = {h.id: i for i, h in enumerate(hypotheses)}
    hypothesis_rows.sort(key=lambda r: order.get(r["id"], 1_000))
    searches = [s for r in hypothesis_rows for s in r.get("searches", [])]
    return {
        "files_scanned": len(file_results),
        "files": file_results,
        "tp_count": sum(r["tp_count"] for r in file_results),
        "fp_count": sum(r["fp_count"] for r in file_results),
        "unverified_count": sum(r["unverified_count"] for r in file_results),
        "hypotheses": hypothesis_rows,
        "hypothesis_status": dict(Counter(r["status"] for r in hypothesis_rows)),
        "searches_run": budget.rg_calls,
        "search_retries": sum(1 for s in searches if s.get("outcome") not in (None, "OK")),
        "published": tallies[STATUS_PUBLISHED],
        "corroborated": tallies[STATUS_CORROBORATED],
        "hallucinated_dropped": tallies[STATUS_HALLUCINATED],
        "suppressed": tallies[STATUS_SUPPRESSED],
        "evidence_levels": dict(levels),
        "learned_rules": learned_rules,
        "planner_error": plan["planner_error"],
        "budget": budget.snapshot(),
        "budget_stopped": any(r.get("status") == STATUS_BUDGET for r in hypothesis_rows),
        "rg_memory_limit_enforced": runner.memory_limit_enforced(),
        "dossier": {
            "entry_points": dossier.entry_point_count,
            "sink_kinds": dossier.sink_kinds_present(),
            "call_graph": dossier.has_call_graph,
            "joern": dossier.has_joern,
        },
        "options": {"profile": options.profile, "test_paths": options.test_paths,
                    "generated_paths": options.generated_paths, "max_hypotheses": options.max_hypotheses,
                    "max_steps": options.max_steps, "workers": workers},
    }


def _collapse(trail: Sequence[str]) -> List[str]:
    out: List[str] = []
    for s in trail:
        if not out or out[-1] != s:
            out.append(s)
    return out
