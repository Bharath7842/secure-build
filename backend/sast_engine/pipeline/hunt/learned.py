"""Learned-rule promotion: turn a search the investigator wrote, which led
to a confirmed vulnerability, into a candidate catalog rule — but only once
it passes checks a human reviewer would ask for.

A candidate is a model-written `search` pattern (or the relaxed variant the
engine substituted) whose shown matches included a published true-positive
sink. It is promoted only when:

1. Python compiles it (the catalog pass runs Python `re`);
2. it matches every confirmed sink line it is credited with (positives);
3. it matches none of the hunt's refuted or verifier-disputed sink lines
   (negatives);
4. its repository-wide match count stays under a noise ceiling
   (NOISE_PER_POSITIVE x positives, at most MAX_REPO_MATCHES).

Promoted rules come out in derived-rule shape (`derived: True`), ready to be
merged onto the catalog like runtime-derived rules; nothing here enables
them by itself.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from pipeline.hunt.rg_runner import RgRunner

NOISE_PER_POSITIVE = 5
MAX_REPO_MATCHES = 50
STATUS_PROMOTED = "promoted"
STATUS_REJECTED = "rejected"

Location = Tuple[str, int]


@dataclass
class Candidate:
    pattern: str
    cwe: str
    title: str
    positives: Set[Location] = field(default_factory=set)


def candidates_from_investigations(
    searches_by_hypothesis: Dict[str, Sequence[Dict[str, Any]]],
    confirmed: Iterable[Dict[str, Any]],
) -> List[Candidate]:
    """`confirmed`: published true-positive findings, each with
    file_path/line/cwe/title and the `hypothesis_id` that found it."""
    found: Dict[str, Candidate] = {}
    for finding in confirmed:
        sink: Location = (finding["file_path"], int(finding["line"]))
        for search in searches_by_hypothesis.get(finding.get("hypothesis_id") or "", []):
            if not search.get("model_written"):
                continue
            shown = {(f, int(ln)) for f, ln in search.get("shown") or []}
            if not any(f == sink[0] and abs(ln - sink[1]) <= 2 for f, ln in shown):
                continue
            pattern = search.get("relaxed_pattern") or search.get("pattern")
            if not pattern:
                continue
            cand = found.setdefault(pattern, Candidate(pattern=pattern, cwe=finding.get("cwe") or "",
                                                       title=finding.get("title") or "Learned pattern"))
            cand.positives.add(sink)
    return list(found.values())


def _line(lines_by_file: Dict[str, List[str]], loc: Location, read) -> str:
    file, line = loc
    if file not in lines_by_file:
        lines_by_file[file] = read(file) or []
    lines = lines_by_file[file]
    return lines[line - 1] if 0 < line <= len(lines) else ""


def evaluate_candidates(
    candidates: Sequence[Candidate],
    *,
    negatives: Iterable[Location],
    runner: RgRunner,
    read_lines,
) -> List[Dict[str, Any]]:
    """`read_lines(file) -> list[str] | None`. Returns one row per candidate
    with status promoted/rejected and the reasons."""
    negatives = list(negatives)
    cache: Dict[str, List[str]] = {}
    rows: List[Dict[str, Any]] = []
    for index, cand in enumerate(candidates, start=1):
        reasons: List[str] = []
        try:
            compiled: Optional[re.Pattern] = re.compile(cand.pattern)
        except re.error as exc:
            compiled = None
            reasons.append(f"not a valid Python regex ({exc})")
        if compiled is not None:
            missed = [loc for loc in cand.positives if not compiled.search(_line(cache, loc, read_lines))]
            if missed:
                reasons.append(f"misses {len(missed)} of its {len(cand.positives)} confirmed sink line(s)")
            hit_negatives = [loc for loc in negatives if compiled.search(_line(cache, loc, read_lines))]
            if hit_negatives:
                reasons.append(f"matches {len(hit_negatives)} refuted/disputed site(s)")
        ceiling = min(MAX_REPO_MATCHES, NOISE_PER_POSITIVE * max(1, len(cand.positives)))
        repo_matches = None
        if not reasons:
            result = runner.search(cand.pattern, max_count_per_file=1000)
            if not result.ok or result.output_truncated or result.timed_out:
                reasons.append("repository-wide match count could not be measured")
            else:
                repo_matches = result.match_count
                if repo_matches > ceiling:
                    reasons.append(f"{repo_matches} matches repository-wide (ceiling {ceiling})")
        row: Dict[str, Any] = {
            "pattern": cand.pattern, "cwe": cand.cwe, "title": cand.title,
            "positives": sorted(f"{f}:{ln}" for f, ln in cand.positives),
            "repo_matches": repo_matches, "noise_ceiling": ceiling,
            "status": STATUS_REJECTED if reasons else STATUS_PROMOTED, "reasons": reasons,
        }
        if not reasons:
            row["rule"] = {
                "id": f"learned-{(cand.cwe or 'cwe').lower()}-{index}",
                "title": f"Learned: {cand.title}"[:200],
                "description": "Promoted from an agentic-hunt search that led to a confirmed finding.",
                "cwe": cand.cwe, "severity": "MEDIUM", "pattern": cand.pattern,
                "languages": ["java"], "derived": True,
            }
        rows.append(row)
    return rows
