"""One count source: the headline numbers are computed once and every rendering
reports the same ones (SAST-00-060)."""

from io import BytesIO

import pytest
from fastapi.testclient import TestClient
from openpyxl import load_workbook

from app import db as db_module
from app.config import settings
from app.db import init_db
from app.main import app
from app.models import Finding, Project, Scan
from app.services import scan_export, scan_runner
from app.services.feedback import effective_scan_findings
from app.services.gates import build_gate_summary
from app.services.scan_export import (
    check_report_consistency,
    count_findings,
    group_findings_by_issue,
)

from tests.auth_helpers import ADMIN_HEADERS, make_user

pytestmark = pytest.mark.integration

HDR = ADMIN_HEADERS


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    settings.use_mock_engine = True
    settings.scan_logs_dir = str(tmp_path / "scan_logs")
    init_db(f"sqlite:///{(tmp_path / 'consistency.db').as_posix()}")
    return TestClient(app)


def _finding(scan_id, title, verdict, severity="HIGH", **extra):
    return Finding(
        scan_id=scan_id, severity=severity, title=title, verdict=verdict, kind=extra.pop("kind", "llm"),
        cwe=extra.pop("cwe", "CWE-89"), rule_id=extra.pop("rule_id", title.lower().replace(" ", "-")),
        file_path=extra.pop("file_path", f"src/{title.replace(' ', '')}.java"), line=extra.pop("line", 3),
        issue_class=extra.pop("issue_class", "security"),
        owasp_category=extra.pop("owasp_category", "A03:2021-Injection"), **extra,
    )


@pytest.fixture()
def seeded(client, monkeypatch):
    """The four-way verdict mix, a grouped regex finding with 5 occurrences, and an SCA row."""
    monkeypatch.setattr(scan_runner, "execute_scan", lambda scan_id: None)
    project_id = client.post(
        "/projects", headers=HDR,
        json={"name": "consistency", "default_git_url": "https://github.com/org/repo.git"},
    ).json()["id"]
    scan_id = client.post(
        "/scans", headers=HDR, json={"project_id": project_id, "commit_sha": "cc"}
    ).json()["scan_id"]
    rows = [
        _finding(scan_id, "SQL injection", "true_positive"),
        _finding(scan_id, "Weak hash", "false_positive", severity="MEDIUM", cwe="CWE-328",
                 owasp_category="A02:2021-Cryptographic-Failures"),
        _finding(scan_id, "Serializable", "unverified", severity="LOW", cwe="CWE-502", kind="regex",
                 rule_id="svuid", issue_class="quality", unresolved_reason="not_reviewed_regex",
                 owasp_category="A08:2021-Software-and-Data-Integrity-Failures"),
        _finding(scan_id, "Command injection", "unverified", cwe="CWE-78", unresolved_reason="llm_missing_verdict",
                 owasp_category="A03:2021-Injection"),
        _finding(scan_id, "Vulnerable dependency", "unverified", severity="CRITICAL", cwe="CWE-1104",
                 kind="sca", rule_id="GHSA-1", file_path="pom.xml", unresolved_reason="not_reviewed_sca",
                 owasp_category="A06:2021-Vulnerable-and-Outdated-Components"),
    ]
    for i in range(5):  # one construct repeated across five files: one group, five occurrences
        rows.append(_finding(
            scan_id, "Hardcoded secret", "unverified", severity="MEDIUM", cwe="CWE-798", kind="regex",
            rule_id="secret", matched_text='password = "x"', file_path=f"src/Config{i}.java",
            unresolved_reason="not_reviewed_regex", owasp_category="A07:2021-Identification-and-Authentication-Failures",
        ))
    with db_module.SessionLocal() as db:
        db.get(Scan, scan_id).status = "success"
        db.add_all(rows)
        db.commit()
    return scan_id


def _grouped(scan_id):
    with db_module.SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        return group_findings_by_issue(effective_scan_findings(db, scan))


# --- count_findings ---------------------------------------------------------

def test_count_findings_splits_every_bucket_by_severity_and_class(seeded):
    counts = count_findings(_grouped(seeded))
    assert counts["totals"] == {
        "true_positive": {"groups": 1, "occurrences": 1},
        "unverified": {"groups": 4, "occurrences": 8},   # 1 + 1 + 1 + the group of five
        "false_positive": {"groups": 1, "occurrences": 1},
    }
    assert counts["by_verdict"]["true_positive"]["high"] == {"groups": 1, "occurrences": 1}
    assert counts["by_verdict"]["unverified"]["medium"] == {"groups": 1, "occurrences": 5}
    assert counts["by_verdict"]["unverified"]["critical"] == {"groups": 1, "occurrences": 1}
    assert counts["by_verdict"]["false_positive"]["medium"] == {"groups": 1, "occurrences": 1}
    assert counts["by_issue_class"]["security"] == {"groups": 5, "occurrences": 9}
    assert counts["by_issue_class"]["quality"] == {"groups": 1, "occurrences": 1}
    assert counts["by_issue_class"]["unclassified"] == {"groups": 0, "occurrences": 0}
    assert counts["dismissed"] == counts["totals"]["false_positive"]
    assert counts["actionable"]["high"] == {"groups": 2, "occurrences": 2}


def test_a_verdict_outside_the_contract_is_counted_not_lost():
    rows = [
        Finding(id="a", scan_id="s", severity="high", title="x", verdict="weird", kind="llm"),
        Finding(id="b", scan_id="s", severity="high", title="y", verdict=None, kind="llm"),
    ]
    counts = count_findings(rows)
    assert counts["totals"]["unknown"] == {"groups": 2, "occurrences": 2}
    assert counts["actionable"]["high"]["groups"] == 2  # it still needs a human, never "dismissed"
    assert counts["dismissed"] == {"groups": 0, "occurrences": 0}


def test_legacy_rows_without_an_issue_class_are_unclassified():
    rows = [Finding(id="a", scan_id="s", severity="low", title="x", verdict="true_positive", kind="llm")]
    assert count_findings(rows)["by_issue_class"]["unclassified"] == {"groups": 1, "occurrences": 1}


# --- every consumer reads it ------------------------------------------------

def test_the_api_totals_come_from_count_findings(client, seeded):
    body = client.get(f"/scans/{seeded}/findings", headers=HDR).json()
    counts = body["severity_group_counts"]
    assert (body["tp_count"], body["unverified_count"], body["fp_count"]) == (
        counts["totals"]["true_positive"]["occurrences"],
        counts["totals"]["unverified"]["occurrences"],
        counts["totals"]["false_positive"]["occurrences"],
    ) == (1, 8, 1)
    assert counts["totals"] == count_findings(_grouped(seeded))["totals"]
    assert counts["by_owasp"] == count_findings(_grouped(seeded))["by_owasp"]


def test_a_verdict_filter_keeps_whole_groups_and_the_unfiltered_counts(client, seeded):
    body = client.get(f"/scans/{seeded}/findings", headers=HDR, params={"verdict": "unverified"}).json()
    assert {f["verdict"] for f in body["findings"]} == {"unverified"}
    assert len(body["findings"]) == 4
    assert body["tp_count"] == 1 and body["fp_count"] == 1  # the totals ignore the filter
    assert body["severity_group_counts"]["totals"]["true_positive"]["groups"] == 1


def test_the_gate_summary_counts_equal_count_findings(seeded):
    grouped = _grouped(seeded)
    counts = count_findings(grouped)
    with db_module.SessionLocal() as db:
        project = db.get(Scan, seeded).project
    gate = build_gate_summary(project, grouped)
    assert gate["total_findings"] == sum(c["groups"] for c in counts["totals"].values()) == len(grouped)
    for sev, n in gate["by_severity"].items():
        assert n == sum(counts["by_verdict"][b][sev]["groups"] for b in counts["by_verdict"])
    assert gate["by_verdict"] == {"TRUE_POSITIVE": 1, "UNVERIFIED": 4, "FALSE_POSITIVE": 1}
    assert gate == build_gate_summary(project, grouped, counts=counts)


def test_a_resolved_confirmed_finding_stops_blocking_the_gate(seeded):
    grouped = _grouped(seeded)
    with db_module.SessionLocal() as db:
        project = db.get(Scan, seeded).project
    project.gate_max_high = 0
    assert build_gate_summary(project, grouped)["gate_failed"] is True
    confirmed = next(f for f in grouped if f.verdict == "true_positive")
    confirmed.review = {"resolution_status": "resolved"}
    assert build_gate_summary(project, grouped)["gate_failed"] is False


# --- check_report_consistency -----------------------------------------------

def test_the_seeded_scan_is_consistent(seeded):
    with db_module.SessionLocal() as db:
        assert check_report_consistency(db, db.get(Scan, seeded)) == []


def test_every_pdf_block_is_counted_in_the_cover_totals(seeded):
    """A section the cover does not count would show up as extra headings."""
    from pypdf import PdfReader

    with db_module.SessionLocal() as db:
        scan = db.get(Scan, seeded)
        data = scan_export.build_pdf_report(scan.project, scan, _grouped_in(db, scan))
    text = " ".join(" ".join(p.extract_text() for p in PdfReader(BytesIO(data)).pages).split())
    import re

    assert len(re.findall(r"FINDING \d+", text)) == 6  # the six groups, nothing more


def _grouped_in(db, scan):
    return group_findings_by_issue(effective_scan_findings(db, scan))


def test_a_pdf_that_drops_a_finding_is_reported_with_its_bucket(seeded, monkeypatch):
    real = scan_export._finding_story_block

    def dropping(idx, finding, **kwargs):
        if finding.title == "Command injection":
            return []
        return real(idx, finding, **kwargs)

    monkeypatch.setattr(scan_export, "_finding_story_block", dropping)
    with db_module.SessionLocal() as db:
        problems = check_report_consistency(db, db.get(Scan, seeded))
    assert any("PDF findings: Unresolved has 3 finding block(s), the cover says 4" in p for p in problems), problems
    assert any("finding heading(s)" in p for p in problems)


def test_an_excel_summary_that_counts_fp_as_actionable_is_reported(seeded, monkeypatch):
    real = scan_export.count_findings

    def lying_summary(grouped):
        counts = real(grouped)
        counts["totals"]["unverified"]["groups"] += counts["totals"]["false_positive"]["groups"]
        return counts

    # Only the workbook's own counting is wrong; the check recounts independently.
    real_build = scan_export.build_excel_report

    def build_with_lie(project, scan, findings):
        monkeypatch.setattr(scan_export, "count_findings", lying_summary)
        try:
            return real_build(project, scan, findings)
        finally:
            monkeypatch.setattr(scan_export, "count_findings", real)

    monkeypatch.setattr(scan_export, "build_excel_report", build_with_lie)
    with db_module.SessionLocal() as db:
        problems = check_report_consistency(db, db.get(Scan, seeded))
    assert any(p.startswith("Excel summary: Unresolved says 5 groups") for p in problems), problems


def test_an_excel_findings_sheet_missing_a_row_is_reported(seeded, monkeypatch):
    real_sheet = scan_export._build_findings_sheet

    def short_sheet(sheet, findings):
        real_sheet(sheet, [f for f in findings if f.title != "Weak hash"])

    monkeypatch.setattr(scan_export, "_build_findings_sheet", short_sheet)
    with db_module.SessionLocal() as db:
        problems = check_report_consistency(db, db.get(Scan, seeded))
    assert any("Excel findings sheet: False Positive lists 0 rows, the summary says 1" in p for p in problems)


def test_an_api_whose_counts_disagree_with_its_rows_is_reported(seeded, monkeypatch):
    real = scan_export.count_findings

    def wrong(grouped):
        counts = real(grouped)
        counts["by_verdict"]["true_positive"]["high"]["groups"] += 1
        return counts

    monkeypatch.setattr(scan_export, "count_findings", wrong)
    with db_module.SessionLocal() as db:
        problems = [p for p in check_report_consistency(db, db.get(Scan, seeded)) if p.startswith("API counts")]
    assert any("Confirmed / high says" in p for p in problems), problems


def test_an_overridden_finding_is_counted_by_its_effective_verdict_everywhere(client, seeded):
    with db_module.SessionLocal() as db:
        confirmed = db.query(Finding).filter(Finding.scan_id == seeded, Finding.title == "SQL injection").one().id
    reviewer = make_user("reviewer@test.local", role="admin")[1]
    assert client.post(
        f"/scans/{seeded}/findings/{confirmed}/review", headers=reviewer,
        json={"decision": "false_positive", "comment": "validated upstream"},
    ).status_code == 200
    with db_module.SessionLocal() as db:
        assert check_report_consistency(db, db.get(Scan, seeded)) == []
    counts = client.get(f"/scans/{seeded}/findings", headers=HDR).json()["severity_group_counts"]
    assert counts["totals"]["true_positive"]["groups"] == 0
    assert counts["totals"]["false_positive"]["groups"] == 2


def test_other_scan_types_have_nothing_to_check(client, seeded):
    with db_module.SessionLocal() as db:
        scan = db.get(Scan, seeded)
        scan.scan_type = "sca"
        db.commit()
        assert check_report_consistency(db, scan) == []


def test_a_real_scan_logs_inconsistencies_without_failing(seeded, monkeypatch):
    lines = []
    monkeypatch.setattr(scan_runner.scan_log, "log", lambda _id, line: lines.append(line))
    monkeypatch.setattr(scan_export, "check_report_consistency", lambda db, scan: ["PDF cover: Confirmed says nope"])
    scan_runner._log_report_consistency(seeded)
    assert lines == ["Warning — report inconsistency: PDF cover: Confirmed says nope"]


def test_a_crashing_check_never_breaks_the_scan(seeded, monkeypatch, caplog):
    def boom(db, scan):
        raise RuntimeError("builder exploded")

    monkeypatch.setattr(scan_export, "check_report_consistency", boom)
    scan_runner._log_report_consistency(seeded)  # must not raise
    assert "could not run" in caplog.text
