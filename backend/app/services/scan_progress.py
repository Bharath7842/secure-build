"""Scan progress helpers — infer % from engine log lines."""

from __future__ import annotations

# Rough progress checkpoints (workspace prep -> agent steps -> persist). The
# agent prints "### <label>" once per step (see sast_engine/sast_scan_agent.py
# AgentTrace) — that's what most of this matches on; the rest are
# scan_runner.py's own pre/post-agent milestones.
PROGRESS_MARKERS: list[tuple[str, int]] = [
    ("Repository ready", 15),
    ("Starting the discovery agent", 20),
    ("### Scanning the repository", 30),
    ("### Detecting the tech stack", 50),
    ("### Categorizing files", 65),
    ("### Mapping module risk", 70),
    ("### Building Joern code property graph", 72),
    ("### Deriving runtime regex", 75),
    ("### Tracing inter-file flows", 80),
    # The deep-scan and triage banners name the risk levels each tier holds
    # in this scan ("### Scanning CRITICAL files (deep scan)", "### Scanning
    # HIGH/MEDIUM/LOW files (triage)"), so they match on their fixed suffix.
    ("files (deep scan)", 85),
    ("files (triage)", 97),
    ("### Running Joern queries", 97),
    ("### Hunting vulnerabilities (agentic)", 97),
    ("### Grouping ", 98),
    ("### Generating report", 99),
    # Fixed-tier labels from before the banners named the actual tiers.
    ("### Scanning CRITICAL/HIGH files", 85),
    ("### Scanning MEDIUM/LOW files", 97),
    ("### Grouping MEDIUM/LOW findings", 98),
    # Pre-rename labels, kept so scans started before the CRITICAL/HIGH vs
    # MEDIUM/LOW split (and any log tail persisted from them) still resolve.
    ("### Scanning CRITICAL/HIGH/MEDIUM files", 85),
    ("### Scanning LOW-risk files", 97),
    # DAST (app/dast/runner.py banners)
    ("### DAST: checking connection", 10),
    ("### DAST: fingerprinting", 15),
    ("### DAST: authenticating", 20),
    ("### DAST: classifying login", 25),
    ("### DAST: logging in", 40),
    ("### DAST: crawling", 55),
    ("### DAST: importing schemas", 65),
    ("### DAST: ingesting schemas", 65),  # the label before it was renamed; kept for persisted logs
    ("### DAST: passive analysis", 70),
    ("### DAST: testing apis", 75),
    ("### DAST: probing browser inputs", 82),
    ("### DAST: checking authorization", 88),
    ("### DAST: finishing", 95),
    # The label the summary banner had before it was renamed `finishing`; kept so persisted logs resolve.
    ("### DAST: summarizing", 95),
]


def infer_progress_from_lines(lines: list[str], *, floor: int = 10) -> int:
    """Return the highest progress % implied by log lines (at least `floor`)."""
    best = floor
    for line in lines:
        for needle, pct in PROGRESS_MARKERS:
            if needle in line and pct > best:
                best = pct
    return best
