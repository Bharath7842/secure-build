"""Tests for log-derived scan progress."""

from app.services.scan_progress import infer_progress_from_lines


def test_infer_progress_from_discovery_step_banners():
    lines = [
        "Starting scan v1 for demo.",
        "Repository ready.",
        "Starting the discovery agent...",
        "### Scanning the repository",
        "### Detecting the tech stack",
    ]
    assert infer_progress_from_lines(lines, floor=10) == 50


def test_infer_progress_reaches_mapping_module_risk():
    lines = ["### Mapping module risk", "Discovery finished — Python, 4 files scanned."]
    assert infer_progress_from_lines(lines, floor=10) == 70


def test_infer_progress_reaches_llm_and_low_scan_banners():
    assert infer_progress_from_lines(
        ["### Scanning CRITICAL/HIGH/MEDIUM files"], floor=10
    ) == 85
    assert infer_progress_from_lines(
        ["### Scanning LOW-risk files"], floor=10
    ) == 97
    assert infer_progress_from_lines(
        ["### Deriving runtime regex"], floor=10
    ) == 75
    assert infer_progress_from_lines(
        ["### Deriving runtime regex", "### Tracing inter-file flows"], floor=10
    ) == 80
    assert infer_progress_from_lines(
        ["### Tracing inter-file flows", "### Scanning CRITICAL/HIGH files"], floor=10
    ) == 85
    assert infer_progress_from_lines(
        ["### Scanning CRITICAL/HIGH/MEDIUM files"], floor=10
    ) == 85
    assert infer_progress_from_lines(
        ["### Scanning LOW-risk files"], floor=10
    ) == 97


def test_infer_progress_monotonic_floor():
    assert infer_progress_from_lines(["### Scanning the repository"], floor=60) == 60


def test_infer_progress_ignores_unrelated_lines():
    assert infer_progress_from_lines(["Cloning https://example.com/r.git..."], floor=10) == 10


def test_tier_banners_resolve_whatever_tiers_they_name():
    from app.services.scan_progress import infer_progress_from_lines

    assert infer_progress_from_lines(["### Scanning CRITICAL files (deep scan)"]) == 85
    assert infer_progress_from_lines(["### Scanning CRITICAL/HIGH files (deep scan)"]) == 85
    assert infer_progress_from_lines(["### Scanning HIGH/MEDIUM/LOW files (triage)"]) == 97
    assert infer_progress_from_lines(["### Hunting vulnerabilities (agentic)"]) == 97
    assert infer_progress_from_lines(["### Grouping HIGH/MEDIUM/LOW findings"]) == 98
    # Persisted logs from before the banners named the tiers.
    assert infer_progress_from_lines(["### Scanning MEDIUM/LOW files"]) == 97
