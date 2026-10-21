"""joern_findings.py — joern/queries.sc hits as unverified findings.

Each hit becomes a finding in exactly the shape ``llm_file_scan.findings_from_hits``
produces for a regex hit (``kind="joern"``, ``verdict="unverified"``), so the
rest of the pipeline — persistence, grouping by (rule_id, matched_text), the
grouped LLM TP/FP confirmation, export — treats it like any other pattern
match. ``rules_for_hits`` builds a ``RegexRule`` per query id purely so the
confirm prompt has a title/CWE/description to show; those rules are never
added to the regex catalog and their pattern never runs.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from pipeline.llm_file_scan import (
    UNVERIFIED_REASON,
    VERDICT_UNVERIFIED,
    build_code_context,
    looks_generated,
    looks_vendored_or_minified,
)
from pipeline.owasp_map import owasp_for_rule
from pipeline.regex_scan import RegexRule

RULE_PREFIX = "joern-"
KIND = "joern"
# Pattern for the synthetic RegexRule — must compile and must never match real
# code, since nothing should ever run it.
_NEVER_MATCHES = r"(?!x)x"


def severity_for_score(score: Any) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "MEDIUM"
    if s >= 8:
        return "CRITICAL"
    if s >= 6:
        return "HIGH"
    if s >= 4:
        return "MEDIUM"
    return "LOW"


def _norm(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def _rule_id(hit: Dict[str, Any]) -> str:
    return RULE_PREFIX + re.sub(r"[^a-z0-9-]+", "-", str(hit.get("query") or "query").lower()).strip("-")


def _iter_hits(results: Iterable[Optional[Dict[str, Any]]]) -> Iterable[Dict[str, Any]]:
    for result in results:
        for hit in (result or {}).get("hits") or []:
            if isinstance(hit, dict) and hit.get("file") and not str(hit["file"]).startswith("<"):
                yield hit


def rules_for_hits(results: Iterable[Optional[Dict[str, Any]]]) -> List[RegexRule]:
    rules: Dict[str, RegexRule] = {}
    for hit in _iter_hits(results):
        rid = _rule_id(hit)
        if rid in rules:
            continue
        rules[rid] = RegexRule({
            "id": rid,
            # Per-query title; the per-hit title (which may name the call)
            # stays on the finding itself.
            "title": str(hit.get("query") or rid).replace("-", " ").capitalize(),
            "description": f"Joern CPG query: {hit.get('description') or ''}".strip(),
            "cwe": hit.get("cwe") or "",
            "severity": severity_for_score(hit.get("score")),
            "category": "joern",
            "pattern": _NEVER_MATCHES,
        })
    return list(rules.values())


def file_results_from_hits(
    results: Iterable[Optional[Dict[str, Any]]],
    repo_root: Path,
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Group hits by file into scan_triage_files-shaped file results.

    Returns (file_results, skipped) where skipped counts generated/vendored
    files dropped the same way the regex/LLM tiers drop them.
    """
    by_file: Dict[str, List[Dict[str, Any]]] = {}
    for hit in _iter_hits(results):
        by_file.setdefault(_norm(str(hit["file"])), []).append(hit)

    skipped = {"generated": 0, "vendored": 0, "unreadable": 0}
    file_results: List[Dict[str, Any]] = []
    for rel, hits in by_file.items():
        try:
            text = (repo_root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            skipped["unreadable"] += 1
            continue
        if looks_generated(text):
            skipped["generated"] += 1
            continue
        if looks_vendored_or_minified(rel, text):
            skipped["vendored"] += 1
            continue
        findings = findings_for_file(rel, text, hits)
        if findings:
            file_results.append({
                "file_path": rel, "chunks": 0, "findings": findings,
                "tp_count": 0, "fp_count": 0, "unverified_count": len(findings),
                "chunk_errors": [],
            })
    return file_results, skipped


def findings_for_file(rel: str, source_text: str, hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, int]] = set()
    for hit in hits:
        rid = _rule_id(hit)
        line = int(hit.get("line") or -1)
        if line <= 0:
            line = 1
        if (rid, line) in seen:
            continue
        seen.add((rid, line))
        cwe = str(hit.get("cwe") or "")
        matched = " ".join(str(hit.get("code") or "").split())
        out.append({
            "rule_id": rid,
            "title": str(hit.get("title") or rid)[:500],
            "severity": severity_for_score(hit.get("score")),
            "cwe": cwe,
            "owasp_category": owasp_for_rule(cwe, None),
            "line": line,
            "snippet": build_code_context(source_text, line, matched),
            "matched_text": matched[:500],
            "group_by_rule": False,
            "derived": False,
            "verdict": VERDICT_UNVERIFIED,
            "unresolved_reason": "not_reviewed_joern",
            "verdict_reason": UNVERIFIED_REASON,
            "kind": KIND,
            "confidence": None,
        })
    return out
