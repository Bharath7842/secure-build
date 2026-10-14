"""Hypothesis planning: deterministic seeds from the dossier, then one LLM
call that ranks and extends them.

The seeds guarantee a floor — every sink kind the repo actually contains,
every unconfirmed static-analysis flow, and the configuration surfaces get a
hypothesis even if the planner call fails or plans badly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

from llm_client import parse_llm_json_array
from pipeline.call_graph import _SINK_SEVERITY
from pipeline.hunt.prompts import PLANNER_SYSTEM
from pipeline.hunt.redact import redact
from pipeline.hunt.repo_index import RepoDossier

STRATEGY_SINK_FIRST = "sink_first"
STRATEGY_SOURCE_FIRST = "source_first"
STRATEGY_CONFIG_FIRST = "config_first"
STRATEGIES = (STRATEGY_SINK_FIRST, STRATEGY_SOURCE_FIRST, STRATEGY_CONFIG_FIRST)
DEFAULT_MAX_HYPOTHESES = 20

# sink kind -> (CWE, vulnerability class, initial strategy)
KIND_PROFILE: Dict[str, tuple] = {
    "sql": ("CWE-89", "SQL injection", STRATEGY_SINK_FIRST),
    "jpa": ("CWE-89", "JPQL/native query injection", STRATEGY_SINK_FIRST),
    "jdbc_template": ("CWE-89", "SQL injection via JdbcTemplate", STRATEGY_SINK_FIRST),
    "command": ("CWE-78", "OS command injection", STRATEGY_SINK_FIRST),
    "eval": ("CWE-94", "Expression/script injection", STRATEGY_SINK_FIRST),
    "ssrf": ("CWE-918", "Server-side request forgery", STRATEGY_SINK_FIRST),
    "ldap": ("CWE-90", "LDAP injection", STRATEGY_SINK_FIRST),
    "deser": ("CWE-502", "Unsafe deserialization", STRATEGY_SINK_FIRST),
    "xxe": ("CWE-611", "XML external entity processing", STRATEGY_SINK_FIRST),
    "xss": ("CWE-79", "Reflected XSS via servlet writer", STRATEGY_SINK_FIRST),
    "response_body": ("CWE-79", "Reflected XSS via HTTP response body", STRATEGY_SOURCE_FIRST),
    "reflect": ("CWE-470", "Unsafe reflection", STRATEGY_SINK_FIRST),
    "files": ("CWE-22", "Path traversal", STRATEGY_SINK_FIRST),
    "redirect": ("CWE-601", "Open redirect", STRATEGY_SINK_FIRST),
    "header": ("CWE-113", "HTTP response header injection", STRATEGY_SINK_FIRST),
    "log": ("CWE-117", "Log injection", STRATEGY_SOURCE_FIRST),
    "crypto": ("CWE-327", "Weak cryptography or randomness", STRATEGY_CONFIG_FIRST),
    "secret": ("CWE-798", "Hardcoded credential", STRATEGY_CONFIG_FIRST),
    "authz": ("CWE-862", "Missing authorization on an endpoint", STRATEGY_SOURCE_FIRST),
    "csrf": ("CWE-352", "CSRF protection disabled", STRATEGY_CONFIG_FIRST),
}
# Hypothesis classes that need no source->sink path (a single construct is
# the vulnerability).
CONFIG_KINDS = frozenset({"crypto", "secret", "csrf"})
ACCESS_CONTROL_KINDS = frozenset({"authz"})
_KIND_RANK = {**_SINK_SEVERITY, "authz": 1, "csrf": 2, "secret": 2, "crypto": 3}


@dataclass
class Hypothesis:
    id: str
    cwe: str
    vuln_class: str
    sink_kind: str
    rationale: str
    priority: int = 3
    initial_strategy: str = STRATEGY_SINK_FIRST
    seed_searches: List[Dict[str, str]] = field(default_factory=list)
    evidence_needed: str = ""
    origin: str = "seed"  # seed | llm | flow
    flow: Optional[Dict[str, Any]] = None

    @property
    def needs_source(self) -> bool:
        return self.sink_kind not in CONFIG_KINDS

    @property
    def access_control(self) -> bool:
        return self.sink_kind in ACCESS_CONTROL_KINDS

    def describe(self) -> str:
        lines = [
            f"Hypothesis {self.id}: {self.vuln_class} ({self.cwe}), sink kind '{self.sink_kind}'",
            f"Why: {self.rationale}",
            f"Start with: {self.initial_strategy}",
        ]
        if self.evidence_needed:
            lines.append(f"Evidence needed: {self.evidence_needed}")
        if self.seed_searches:
            lines.append("Suggested first searches:")
            for s in self.seed_searches[:4]:
                lines.append(f"  - {s.get('intent', '')}: /{s.get('pattern', '')}/" + (f" in {s['glob']}" if s.get("glob") else ""))
        if self.flow:
            hops = self.flow.get("hops") or []
            lines.append("Static analysis proposed this unconfirmed flow:")
            for h in hops:
                lines.append(f"  - {h.get('role')}: {h.get('file')}:{h.get('line')} {h.get('fqcn', '').rsplit('.', 1)[-1]}.{h.get('name', '')}")
        return "\n".join(lines)


def _kind_key(kind: str) -> int:
    return _KIND_RANK.get(kind, 5)


def seed_hypotheses(
    dossier: RepoDossier,
    *,
    flow_candidates: Sequence[Dict[str, Any]] = (),
    max_flows: int = 5,
) -> List[Hypothesis]:
    seeds: List[Hypothesis] = []
    present = {s.kind: s for s in dossier.sinks if s.file_count > 0}
    for kind in sorted(present, key=_kind_key):
        if kind not in KIND_PROFILE:
            continue
        cwe, vuln_class, strategy = KIND_PROFILE[kind]
        inv = present[kind]
        seeds.append(Hypothesis(
            id=f"S{len(seeds) + 1}", cwe=cwe, vuln_class=vuln_class, sink_kind=kind,
            rationale=f"{inv.file_count} file(s) contain {kind} sinks ({inv.resolution})",
            priority=2 if _kind_key(kind) <= 1 else 3, initial_strategy=strategy,
            evidence_needed=(
                "the offending construct and its context" if kind in CONFIG_KINDS
                else "an untrusted source reaching the sink without sanitization"
                if kind not in ACCESS_CONTROL_KINDS
                else "a state-changing endpoint with no authorization check"
            ),
        ))
    if dossier.entry_point_count and "authz" not in present:
        cwe, vuln_class, strategy = KIND_PROFILE["authz"]
        seeds.append(Hypothesis(
            id=f"S{len(seeds) + 1}", cwe=cwe, vuln_class=vuln_class, sink_kind="authz",
            rationale=f"{dossier.entry_point_count} entry point(s); no authorization annotations seen",
            priority=2, initial_strategy=strategy,
            evidence_needed="a state-changing endpoint with no authorization check",
        ))
    # One hypothesis per (sink kind, sink file): several flows into the same
    # sink are one investigation, not several near-identical ones.
    seen_sinks: set = set()
    unique_flows = []
    for f in flow_candidates:
        hops = f.get("hops") or []
        if not hops:
            continue
        key = (f.get("sink_kind"), hops[-1].get("file"))
        if key not in seen_sinks:
            seen_sinks.add(key)
            unique_flows.append(f)
    for flow in unique_flows[:max_flows]:
        kind = str(flow.get("sink_kind") or "")
        cwe, vuln_class, _strategy = KIND_PROFILE.get(kind, ("", f"{kind} flow", STRATEGY_SINK_FIRST))
        seeds.append(Hypothesis(
            id=f"F{len(seeds) + 1}", cwe=cwe or "CWE-20", vuln_class=f"{vuln_class} (static-analysis flow)",
            sink_kind=kind or "other", rationale="unconfirmed cross-file flow from the call graph",
            priority=1, initial_strategy=STRATEGY_SINK_FIRST, origin="flow", flow=flow,
            evidence_needed="whether the flow's source value actually reaches the sink unsanitized",
        ))
    return seeds


def _coerce_hypothesis(raw: Dict[str, Any], index: int) -> Optional[Hypothesis]:
    if not isinstance(raw, dict):
        return None
    kind = str(raw.get("sink_kind") or "other").strip().lower()
    profile = KIND_PROFILE.get(kind)
    cwe = str(raw.get("cwe") or (profile[0] if profile else "")).strip().upper()
    if not re.fullmatch(r"CWE-\d{1,5}", cwe):
        return None
    vuln_class = str(raw.get("vuln_class") or (profile[1] if profile else "")).strip()[:120]
    if not vuln_class:
        return None
    strategy = str(raw.get("initial_strategy") or "").strip()
    if strategy not in STRATEGIES:
        strategy = profile[2] if profile else STRATEGY_SINK_FIRST
    try:
        priority = min(5, max(1, int(raw.get("priority") or 3)))
    except (TypeError, ValueError):
        priority = 3
    seeds = []
    for s in (raw.get("seed_searches") or [])[:4]:
        if isinstance(s, dict) and s.get("pattern"):
            seeds.append({
                "intent": str(s.get("intent") or "")[:120],
                "pattern": str(s["pattern"])[:400],
                "glob": str(s.get("glob") or "")[:200],
            })
    return Hypothesis(
        id=f"H{index}", cwe=cwe, vuln_class=vuln_class, sink_kind=kind,
        rationale=str(raw.get("rationale") or "")[:300], priority=priority,
        initial_strategy=strategy, seed_searches=seeds,
        evidence_needed=str(raw.get("evidence_needed") or "")[:300], origin="llm",
    )


def plan_hypotheses(
    dossier: RepoDossier,
    seeds: Sequence[Hypothesis],
    *,
    llm: Optional[Callable[..., str]],
    max_hypotheses: int = DEFAULT_MAX_HYPOTHESES,
) -> Dict[str, Any]:
    """Merge seeds with the planner's ranked hypotheses. Returns
    {"hypotheses": [...], "planner_error": str|None}."""
    planned: List[Hypothesis] = []
    error: Optional[str] = None
    if llm is not None:
        user = (
            "Repository dossier:\n<untrusted_code file=\"(dossier)\">\n"
            + redact(dossier.render())
            + "\n</untrusted_code>\n\nHypotheses already queued from the dossier (you may re-rank, "
            "refine or add to them; do not repeat them verbatim):\n"
            + "\n".join(f"- {h.vuln_class} ({h.cwe}) — {h.rationale}" for h in seeds)
            + f"\n\nReturn at most {max_hypotheses} hypotheses, each with at most 2 seed searches and "
            "one-sentence rationale/evidence_needed. Skip vulnerability classes the dossier gives no "
            "reason to suspect."
        )
        try:
            # Sized for max_hypotheses compact entries; a truncated plan used to
            # lose its tail to salvage parsing.
            raw = llm(PLANNER_SYSTEM, user, max_tokens=min(8192, 600 + 350 * max_hypotheses), step="hunt_plan")
            items, error = parse_llm_json_array(raw)
            planned = [h for h in (_coerce_hypothesis(it, i + 1) for i, it in enumerate(items)) if h]
            if planned:
                error = None
        except Exception as exc:  # noqa: BLE001 — seeds still run
            error = f"{type(exc).__name__}: {exc}"

    merged: List[Hypothesis] = []
    seen: Dict[tuple, Hypothesis] = {}
    # Flow seeds first (concrete leads), then the planner's ranking, then the
    # remaining dossier seeds.
    ordered = (
        [h for h in seeds if h.origin == "flow"]
        + sorted(planned, key=lambda h: h.priority)
        + sorted([h for h in seeds if h.origin != "flow"], key=lambda h: (h.priority, _kind_key(h.sink_kind)))
    )
    for h in ordered:
        key = (h.cwe, h.sink_kind) if h.origin != "flow" else (h.id,)
        if key in seen:
            existing = seen[key]
            # Keep the planner's searches on a seed it re-proposed.
            if not existing.seed_searches and h.seed_searches:
                existing.seed_searches = h.seed_searches
            continue
        seen[key] = h
        merged.append(h)
    return {"hypotheses": merged[:max_hypotheses], "planner_error": error}
