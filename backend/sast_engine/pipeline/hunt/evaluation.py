"""Accuracy scoring for the hunt against public SAST benchmarks.

* OWASP Benchmark Java — one test case per BenchmarkTestNNNNN.java with a
  ground-truth row in expectedresults-<version>.csv
  (`BenchmarkTest00001,pathtraver,true,22`). A test case is flagged when any
  finding in its file has a CWE in the same family as the expected CWE,
  mirroring the Benchmark scorecard. Reports TPR/FPR per category and the
  Youden score (TPR - FPR) the scorecard ranks tools by.
* Juliet Java (NIST SARD) — every test file holds a vulnerable `bad*` method
  and safe `good*` variants. A finding counts as a TP when it sits inside a
  `bad*` method (or a `*badSink*` helper) and as an FP inside a `good*` one;
  per-file results roll up per CWE directory.

Pure functions over finding dicts, so the same scoring runs on catalog-only
and catalog+hunt results for a before/after comparison.
"""

from __future__ import annotations

import csv
import re
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from pipeline.hunt.validator import cwe_family

_BENCH_FILE_RE = re.compile(r"(BenchmarkTest\d{5})\.java$")
_METHOD_DECL_RE = re.compile(
    r"^\s*(?:public|private|protected|static|final|synchronized|\s)*[\w<>\[\],\s]+\s+(\w+)\s*\([^;]*\)\s*(?:throws[^{]*)?\{?\s*$"
)
_JULIET_CWE_RE = re.compile(r"CWE(\d+)_")


def _norm_cwe(raw: Any) -> str:
    text = str(raw or "").strip().upper()
    if text.isdigit():
        return f"CWE-{text}"
    match = re.search(r"CWE-?(\d+)", text)
    return f"CWE-{match.group(1)}" if match else text


def load_benchmark_expected(csv_path: Path | str) -> Dict[str, Dict[str, Any]]:
    """{test_name: {"category", "real", "cwe"}} from expectedresults-*.csv."""
    expected: Dict[str, Dict[str, Any]] = {}
    with open(csv_path, newline="", encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if not row or row[0].lstrip().startswith("#") or len(row) < 4:
                continue
            name, category, real, cwe = (cell.strip() for cell in row[:4])
            expected[name] = {"category": category, "real": real.lower() == "true", "cwe": _norm_cwe(cwe)}
    return expected


def score_owasp_benchmark(
    findings: Iterable[Dict[str, Any]],
    expected: Dict[str, Dict[str, Any]],
    *,
    verdicts: Sequence[str] = ("true_positive", "unverified"),
) -> Dict[str, Any]:
    """`verdicts`: which finding verdicts count as "flagged" (a tool's
    unverified output is still output a user has to triage)."""
    flagged_families: Dict[str, set] = defaultdict(set)
    for f in findings:
        if f.get("verdict") not in verdicts:
            continue
        match = _BENCH_FILE_RE.search(str(f.get("file_path") or ""))
        if match:
            flagged_families[match.group(1)].add(cwe_family(_norm_cwe(f.get("cwe"))))

    per_category: Dict[str, Dict[str, int]] = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0, "tn": 0})
    for name, truth in expected.items():
        hit = cwe_family(truth["cwe"]) in flagged_families.get(name, set())
        bucket = per_category[truth["category"]]
        if truth["real"]:
            bucket["tp" if hit else "fn"] += 1
        else:
            bucket["fp" if hit else "tn"] += 1
    return _summarize(per_category)


def _summarize(per_category: Dict[str, Dict[str, int]]) -> Dict[str, Any]:
    rows: Dict[str, Dict[str, Any]] = {}
    totals = {"tp": 0, "fn": 0, "fp": 0, "tn": 0}
    for category, c in sorted(per_category.items()):
        for k in totals:
            totals[k] += c[k]
        rows[category] = {**c, **_rates(c)}
    scores = [r["score"] for r in rows.values()]
    return {
        "categories": rows,
        "overall": {**totals, **_rates(totals)},
        # The scorecard's headline: the mean of per-category Youden scores.
        "average_score": round(sum(scores) / len(scores), 4) if scores else 0.0,
    }


def _rates(c: Dict[str, int]) -> Dict[str, float]:
    tpr = c["tp"] / (c["tp"] + c["fn"]) if (c["tp"] + c["fn"]) else 0.0
    fpr = c["fp"] / (c["fp"] + c["tn"]) if (c["fp"] + c["tn"]) else 0.0
    return {"tpr": round(tpr, 4), "fpr": round(fpr, 4), "score": round(tpr - fpr, 4)}


def enclosing_method_name(lines: Sequence[str], line: int) -> Optional[str]:
    """Name of the method declared closest above `line` (good enough for
    Juliet's flat, one-method-per-block test files)."""
    for idx in range(min(line, len(lines)) - 1, -1, -1):
        match = _METHOD_DECL_RE.match(lines[idx])
        if match and match.group(1) not in ("if", "for", "while", "switch", "catch", "synchronized"):
            return match.group(1)
    return None


def score_juliet(
    findings: Iterable[Dict[str, Any]],
    repo_root: Path | str,
    *,
    verdicts: Sequence[str] = ("true_positive", "unverified"),
) -> Dict[str, Any]:
    root = Path(repo_root)
    by_file: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for f in findings:
        if f.get("verdict") in verdicts and f.get("file_path"):
            by_file[str(f["file_path"])].append(f)

    per_cwe: Dict[str, Dict[str, int]] = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0, "tn": 0})
    for path in sorted(root.rglob("CWE*.java")):
        rel = path.relative_to(root).as_posix()
        cwe_match = _JULIET_CWE_RE.search(PurePosixPath(rel).name)
        if not cwe_match:
            continue
        cwe = f"CWE-{cwe_match.group(1)}"
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        has_bad = re.search(r"\bvoid\s+bad\w*\s*\(", text) is not None
        has_good = re.search(r"\b(?:void|\w+)\s+good\w*\s*\(", text) is not None
        bad_hit = good_hit = False
        for f in by_file.get(rel, []):
            if cwe_family(_norm_cwe(f.get("cwe"))) != cwe_family(cwe):
                continue
            name = (enclosing_method_name(lines, int(f.get("line") or 0)) or "").lower()
            if name.startswith("bad") or "badsink" in name or "badsource" in name:
                bad_hit = True
            elif name.startswith("good"):
                good_hit = True
        bucket = per_cwe[cwe]
        if has_bad:
            bucket["tp" if bad_hit else "fn"] += 1
        if has_good:
            bucket["fp" if good_hit else "tn"] += 1
    return _summarize(per_cwe)


def findings_from_report_files(file_results: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Flatten engine `*_scan_results["files"]` lists into finding dicts that
    carry their file_path."""
    out: List[Dict[str, Any]] = []
    for fr in file_results:
        for f in fr.get("findings") or []:
            out.append({**f, "file_path": f.get("file_path") or fr.get("file_path")})
    return out


def compare(baseline: Dict[str, Any], candidate: Dict[str, Any]) -> Dict[str, Any]:
    """Headline deltas between two score summaries (e.g. catalog-only vs
    catalog+hunt)."""
    b, c = baseline["overall"], candidate["overall"]
    return {
        "tpr_delta": round(c["tpr"] - b["tpr"], 4),
        "fpr_delta": round(c["fpr"] - b["fpr"], 4),
        "score_delta": round(candidate["average_score"] - baseline["average_score"], 4),
        "tp_gained": c["tp"] - b["tp"],
        "fp_gained": c["fp"] - b["fp"],
    }


__all__: Tuple[str, ...] = (
    "compare", "enclosing_method_name", "findings_from_report_files", "load_benchmark_expected",
    "score_juliet", "score_owasp_benchmark",
)
