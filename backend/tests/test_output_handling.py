"""LLM05 guardrails: what a model (or a repository) writes is data in every output.

Engine side: stored fields are sanitised, identifiers have a format, one answer
cannot flood the store. Export side: a title or package name that starts a formula,
carries an XML-illegal character or a quote cannot run, break a file or break out of
an attribute."""

import json
import sys
import zipfile
from io import BytesIO
from pathlib import Path

import pytest

_ENGINE = Path(__file__).resolve().parents[1] / "sast_engine"
if str(_ENGINE) not in sys.path:
    sys.path.insert(0, str(_ENGINE))

try:  # the XML parsed below is our own export, but prefer the hardened parser when present
    from defusedxml import ElementTree as ET
except ImportError:  # pragma: no cover
    import xml.etree.ElementTree as ET

pytestmark = pytest.mark.unit


@pytest.fixture()
def lfs():
    pytest.importorskip("boto3", reason="pipeline modules import llm_client")
    pytest.importorskip("tree_sitter")
    from pipeline import llm_file_scan

    return llm_file_scan


def _raw(**extra):
    return {"line": 1, "verdict": "true_positive", "confidence": 0.9, "rule_id": "r", "title": "t",
            "cwe": "CWE-89", "severity": "HIGH", "verdict_reason": "why", "ai_fix": "fix", **extra}


def _norm(lfs, raw, usage=None):
    return lfs.normalize_finding(raw, file_path="A.java", chunk_start=1, chunk_end=10, usage=usage, step="s")


# --- engine: text, identifiers, volume ------------------------------------------------------

@pytest.mark.parametrize("dirty, clean", [
    ("\x1b[31mred\x1b[0m text", "red text"),
    ("title\x1b]0;evil\x07 here", "title here"),
    ("a\x00b\x07c\x7fd", "abcd"),
    ("line one\r\nline two\rline three", "line one\nline two\nline three"),
    ("abc‮def⁦ghi", "abcdefghi"),  # bidi overrides ("trojan source")
    ("  padded  ", "padded"),
])
def test_stored_model_text_has_no_terminal_escapes_control_chars_or_bidi_overrides(lfs, dirty, clean):
    assert lfs.sanitize_model_text(dirty, 100) == clean


def test_newlines_and_tabs_are_kept_for_multi_line_fields(lfs):
    assert lfs.sanitize_model_text("a\n\tb", 100) == "a\n\tb"


def test_every_stored_field_is_sanitised_and_capped(lfs):
    usage = {}
    out = _norm(lfs, _raw(
        title="\x1b[1mTitle\x1b[0m" + "x" * 900, verdict_reason="r\x00" + "y" * 5000, ai_fix="f" * 9000,
        source="s\x07" * 400, sink="k" * 999, data_flow="d" * 999, snippet="\x1b[0m" + "z" * 2000,
    ), usage)
    assert out["title"].startswith("Title") and len(out["title"]) == 500
    assert len(out["verdict_reason"]) == lfs.MODEL_REASON_MAX_CHARS and "\x00" not in out["verdict_reason"]
    assert len(out["ai_fix"]) == lfs.MODEL_FIX_MAX_CHARS
    assert len(out["source"]) <= 300 and "\x07" not in out["source"]
    assert len(out["sink"]) == 300 and len(out["data_flow"]) == 600 and len(out["snippet"]) == 800
    assert usage["_counters"]["output_validation"]["text_sanitized"] >= 3


@pytest.mark.parametrize("value, expected", [
    ("CWE-89", "CWE-89"), ("cwe-89", "CWE-89"), ("89", "CWE-89"), (89, "CWE-89"), ("CWE-089", "CWE-89"),
    ("CWE-89: SQL Injection", "CWE-89"), ("CWE 79", "CWE-79"), ("CWE-1004", "CWE-1004"),
    ("N/A", None), ("unknown", None), ("", None), (None, None), ("CWE-", None), ("CWE-123456", None),
])
def test_a_cwe_is_normalised_to_cwe_dash_number_or_dropped(lfs, value, expected):
    assert lfs.normalize_model_cwe(value) == expected


def test_a_finding_with_a_junk_cwe_has_no_cwe_instead_of_a_junk_one(lfs):
    usage = {}
    assert _norm(lfs, _raw(cwe="whatever"), usage)["cwe"] is None
    assert usage["_counters"]["output_validation"]["cwe_invalid"] == 1
    assert _norm(lfs, _raw(cwe="89"))["cwe"] == "CWE-89"


@pytest.mark.parametrize("rule_id", ["bad id", "x" * 81, "a\nb", "<script>", "rule/../id", "💥"])
def test_a_rule_id_that_is_not_an_identifier_becomes_llm_extra(lfs, rule_id):
    usage = {}
    assert _norm(lfs, _raw(rule_id=rule_id), usage)["rule_id"] == "llm-extra"
    assert usage["_counters"]["output_validation"]["rule_id_replaced"] == 1


def test_a_normal_rule_id_is_kept(lfs):
    assert _norm(lfs, _raw(rule_id="java-sql.string:concat_1"))["rule_id"] == "java-sql.string:concat_1"


def test_one_answer_cannot_carry_more_than_the_cap(lfs):
    usage = {}
    answer = json.dumps({"findings": [_raw(line=1, title=f"t{i}") for i in range(lfs.MAX_FINDINGS_PER_RESPONSE + 30)]})
    result = lfs.scan_chunk(
        file_path="A.java", chunk={"text": "int a;\n", "start_line": 1, "end_line": 1}, catalog=[], stack_context="",
        usage=usage, call_llm_fn=lambda *a, **k: answer,
    )
    assert len(result["findings"]) == lfs.MAX_FINDINGS_PER_RESPONSE
    assert usage["_counters"]["output_validation"]["findings_truncated"] == 30


def test_the_group_confirm_and_triage_answers_are_sanitised_too(lfs):
    result = lfs._confirm_result_from_item(
        {"verdict": "true_positive", "confidence": 0.9, "verdict_reason": "\x1b[31mbad\x00", "ai_fix": "fix\x07"},
    )
    assert result["verdict_reason"] == "bad" and result["ai_fix"] == "fix"


# --- exports --------------------------------------------------------------------------------

from fastapi.testclient import TestClient  # noqa: E402
from openpyxl import Workbook, load_workbook  # noqa: E402

from app import db as db_module  # noqa: E402
from app.config import settings  # noqa: E402
from app.db import init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Finding, Scan  # noqa: E402
from app.services import feedback, scan_export, scan_runner  # noqa: E402

from tests.auth_helpers import ADMIN_HEADERS as HDR  # noqa: E402

FORMULAS = ['=HYPERLINK("http://evil.example","click")', "+SUM(A1:A9)", "-2+3", "@SUM(1)", "\t=1+1", "=cmd|' /C calc'!A0"]


def test_protect_workbook_text_stores_formula_looking_strings_as_text():
    wb = Workbook()
    sheet = wb.active
    for i, text in enumerate(FORMULAS + ["plain", "x=1", "—", 42], start=1):
        sheet.cell(i, 1, text)
    scan_export.protect_workbook_text(wb)
    buf = BytesIO()
    wb.save(buf)
    reloaded = load_workbook(BytesIO(buf.getvalue())).active
    for i, text in enumerate(FORMULAS, start=1):
        cell = reloaded.cell(i, 1)
        assert cell.value == text and cell.data_type == "s", text
    with zipfile.ZipFile(BytesIO(buf.getvalue())) as archive:
        assert b"<f>" not in archive.read("xl/worksheets/sheet1.xml")  # nothing is a formula
    assert reloaded.cell(len(FORMULAS) + 4, 1).value == 42


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_MOCK_ENGINE", "true")
    monkeypatch.setattr(settings, "use_mock_engine", True)
    monkeypatch.setattr(settings, "scan_logs_dir", str(tmp_path / "scan_logs"))
    init_db(f"sqlite:///{(tmp_path / 'out.db').as_posix()}")
    return TestClient(app)


@pytest.fixture()
def hostile_scan(client, monkeypatch):
    monkeypatch.setattr(scan_runner, "execute_scan", lambda scan_id: None)
    project_id = client.post("/projects", headers=HDR, json={
        "name": "out", "default_git_url": "https://github.com/org/repo.git"}).json()["id"]
    scan_id = client.post("/scans", headers=HDR, json={"project_id": project_id, "commit_sha": "h1"}).json()["scan_id"]
    with db_module.SessionLocal() as db:
        db.get(Scan, scan_id).status = "success"
        db.add_all([
            Finding(scan_id=scan_id, severity="HIGH", title='=HYPERLINK("http://evil.example","x")', cwe="CWE-89",
                    rule_id='a"b', file_path="A.java", line=1, verdict="true_positive", kind="llm",
                    snippet="q = 1\x00\x1b[31m", verdict_reason="+cmd", ai_fix="@SUM(1)"),
            Finding(scan_id=scan_id, severity="LOW", title='Say "hi" <b>&</b>', cwe="CWE-79", rule_id="x",
                    file_path="B.java", line=2, verdict="false_positive", kind="llm"),
            Finding(scan_id=scan_id, severity="HIGH", title="Undecided", cwe="CWE-22", rule_id="r",
                    file_path="C.java", line=3, verdict="unverified", unresolved_reason="not_reviewed_regex",
                    kind="regex"),
        ])
        db.commit()
    return scan_id


def test_the_findings_workbook_has_no_formula_cells(client, hostile_scan):
    resp = client.get(f"/scans/{hostile_scan}/export.xlsx", headers=HDR)
    assert resp.status_code == 200
    with zipfile.ZipFile(BytesIO(resp.content)) as archive:
        for name in archive.namelist():
            if name.startswith("xl/worksheets/"):
                assert b"<f>" not in archive.read(name), name
    sheet = load_workbook(BytesIO(resp.content))["Findings"]
    titles = {row[0].value for row in sheet.iter_rows(min_row=2)} | {
        c.value for row in sheet.iter_rows(min_row=2) for c in row}
    assert '=HYPERLINK("http://evil.example","x")' in titles  # kept verbatim, as text


def test_the_decision_diff_workbook_is_protected_too(client, hostile_scan):
    with db_module.SessionLocal() as db:
        scan = db.get(Scan, hostile_scan)
        base = Scan(project_id=scan.project_id, git_url=scan.git_url, status="success", version=99)
        db.add(base)
        db.commit()
        base_id = base.id
    resp = client.get(f"/scans/{hostile_scan}/decision-diff.xlsx?base={base_id}", headers=HDR)
    if resp.status_code == 200:  # the diff needs occurrence ids; when it refuses there is nothing to protect
        with zipfile.ZipFile(BytesIO(resp.content)) as archive:
            for name in archive.namelist():
                if name.startswith("xl/worksheets/"):
                    assert b"<f>" not in archive.read(name)


def test_the_review_csv_prefixes_formula_cells_and_leaves_ndjson_alone():
    record = {"title": "=1+1", "snippet": "+x", "label": "-y", "rule_id": "@r", "line": 5, "file_path": "ok"}
    body, media = feedback.render_export([record], "csv")
    assert media == "text/csv"
    row = body.splitlines()[1]
    assert "'=1+1" in row and "'+x" in row and "'-y" in row and "'@r" in row and "ok" in row
    ndjson, media = feedback.render_export([record], "ndjson")
    assert json.loads(ndjson.splitlines()[0])["title"] == "=1+1"


def test_the_junit_report_is_well_formed_whatever_the_title_holds(client, hostile_scan):
    resp = client.get(f"/scans/{hostile_scan}/export.junit", headers=HDR)
    assert resp.status_code == 200
    root = ET.fromstring(resp.content)  # raises on an unescaped quote or an illegal character
    cases = {tc.get("name"): tc for tc in root.iter("testcase")}
    assert 'Say "hi" <b>&</b>' in cases
    assert root.get("tests") == "3"
    body = "".join(f.text or "" for f in root.iter("failure"))
    assert "\x00" not in body and "\x1b" not in body


def test_the_sarif_report_marks_undecided_findings_as_notes_and_dismissed_ones_as_suppressed(client, hostile_scan):
    sarif = client.get(f"/scans/{hostile_scan}/export.sarif", headers=HDR).json()
    results = {r["message"]["text"]: r for r in sarif["runs"][0]["results"]}
    undecided = results["Undecided"]
    assert undecided["level"] == "note" and "suppressions" not in undecided
    assert undecided["properties"]["aiAssisted"] is False  # a regex hit nobody reviewed
    dismissed = results['Say "hi" <b>&</b>']
    assert dismissed["suppressions"][0]["kind"] == "external"
    confirmed = results['=HYPERLINK("http://evil.example","x")']
    assert confirmed["level"] == "error" and confirmed["properties"]["aiAssisted"] is True
