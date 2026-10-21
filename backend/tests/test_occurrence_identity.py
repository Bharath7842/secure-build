"""Stable occurrence identity and the scan version stamp (SAST-00-040)."""

import shutil
import sys
from pathlib import Path

import pytest

pytest.importorskip("langgraph")
pytest.importorskip("tree_sitter_java")

from app.config import settings  # noqa: E402
from app.db import init_db  # noqa: E402
from app.models import Finding, Project, Scan  # noqa: E402
from app.services import scan_versions  # noqa: E402
from app.services.agent_bridge import _load_agent_module  # noqa: E402
from app.services.occurrence import occurrence_id  # noqa: E402
from app.services.scan_runner import _make_findings_writer  # noqa: E402

_ENGINE_DIR = Path(__file__).resolve().parents[1] / "sast_engine"
_FIXTURES = Path(__file__).parent / "fixtures" / "identity"


@pytest.fixture()
def occurrence(monkeypatch):
    monkeypatch.setattr(settings, "sast_framework_path", str(_ENGINE_DIR))
    sys.modules.pop("sast_scan_agent", None)
    _load_agent_module()
    return sys.modules["pipeline.occurrence"]


def _finding(path, line, **overrides):
    finding = {
        "kind": "regex", "rule_id": "log-injection", "cwe": "CWE-117",
        "matched_text": "log.info(x)", "file_path": path, "line": line,
    }
    finding.update(overrides)
    return finding


def _stamped(occurrence, root, name, lines):
    findings = [_finding(name, line) for line in lines]
    occurrence.stamp_identity(root, name, findings)
    return findings


def _ids(findings, project="p1"):
    return [occurrence_id(project, f) for f in findings]


@pytest.fixture()
def root(tmp_path):
    for source in _FIXTURES.iterdir():
        shutil.copy(source, tmp_path / source.name)
    return tmp_path


def test_stamping_resolves_the_enclosing_method_and_ordinal(occurrence, root):
    findings = _stamped(occurrence, root, "Orders.java", [7, 8, 12])
    assert [f["enclosing_method"] for f in findings] == [
        "Orders.first(String)", "Orders.first(String)", "Orders.second(String)",
    ]
    assert [f["sink_ordinal"] for f in findings] == [0, 1, 0]
    assert {f["identity_quality"] for f in findings} == {"exact"}
    assert findings[0]["sink_expression"] == "log.info(x)"


def test_the_same_file_scanned_twice_gives_identical_ids(occurrence, root):
    first = _ids(_stamped(occurrence, root, "Orders.java", [7, 8, 12]))
    second = _ids(_stamped(occurrence, root, "Orders.java", [7, 8, 12]))
    assert first == second
    assert len(set(first)) == 3


def test_shifted_lines_keep_the_ids_and_change_only_the_lines(occurrence, root):
    original = _stamped(occurrence, root, "Orders.java", [7, 8, 12])
    shifted = _stamped(occurrence, root, "Orders_shifted.java", [13, 14, 18])
    # Same code under a different file name would change the id; compare the
    # identity parts that do not include the path.
    for a, b in zip(original, shifted):
        assert a["enclosing_method"] == b["enclosing_method"]
        assert a["sink_ordinal"] == b["sink_ordinal"]
        assert a["line"] != b["line"]
    renamed_path = [dict(f, file_path="Orders.java") for f in shifted]
    assert _ids(renamed_path) == _ids(original)


def test_renaming_a_method_changes_only_that_methods_ids(occurrence, root):
    original = _stamped(occurrence, root, "Orders.java", [7, 8, 12])
    renamed = _stamped(occurrence, root, "Orders_renamed.java", [7, 8, 12])
    renamed = [dict(f, file_path="Orders.java") for f in renamed]
    before, after = _ids(original), _ids(renamed)
    assert before[0] != after[0] and before[1] != after[1]
    assert before[2] == after[2]


def test_two_identical_calls_in_one_method_are_two_occurrences(occurrence, root):
    ids = _ids(_stamped(occurrence, root, "Orders.java", [7, 8]))
    assert ids[0] != ids[1]


def test_a_different_sink_expression_is_a_different_occurrence(occurrence, root):
    one = _stamped(occurrence, root, "Orders.java", [7])[0]
    other = dict(one, sink_expression="log.warn(x)")
    assert occurrence_id("p1", one) != occurrence_id("p1", other)


def test_a_different_project_is_a_different_identity(occurrence, root):
    finding = _stamped(occurrence, root, "Orders.java", [7])
    assert _ids(finding, "p1") != _ids(finding, "p2")


def test_a_finding_in_a_yaml_file_is_file_level(occurrence, root):
    finding = {"kind": "regex", "rule_id": "secret", "cwe": "CWE-798",
               "matched_text": "password: hunter2", "file_path": "config.yaml", "line": 2}
    occurrence.stamp_identity(root, "config.yaml", [finding])
    assert finding["identity_quality"] == "file_level"
    assert finding["enclosing_method"] is None
    assert occurrence_id("p1", finding)


def test_a_missing_file_still_yields_an_identity(occurrence, tmp_path):
    finding = _finding("Gone.java", 3)
    occurrence.stamp_identity(tmp_path, "Gone.java", [finding])
    assert finding["identity_quality"] == "file_level"


def test_an_llm_finding_uses_its_sink_then_the_flagged_line(occurrence, root):
    with_sink = {"kind": "llm", "rule_id": "llm-extra", "cwe": "CWE-117", "sink": "log.info( x )",
                 "file_path": "Orders.java", "line": 12}
    without = {"kind": "llm", "rule_id": "llm-extra", "cwe": "CWE-117", "sink": "",
               "snippet": "twenty lines\nof context", "file_path": "Orders.java", "line": 12}
    occurrence.stamp_identity(root, "Orders.java", [with_sink, without])
    assert with_sink["sink_expression"] == "log.info( x )"
    assert without["sink_expression"] == "log.info(x);"


def test_a_paraphrased_sink_falls_back_to_ordering_within_the_method(occurrence, root):
    one = {"kind": "llm", "rule_id": "llm-extra", "cwe": "CWE-117", "sink": "the logger call",
           "file_path": "Orders.java", "line": 7}
    two = dict(one, line=8)
    occurrence.stamp_identity(root, "Orders.java", [one, two])
    assert [one["sink_ordinal"], two["sink_ordinal"]] == [0, 1]


def test_typescript_and_python_methods_are_resolved(occurrence, tmp_path):
    (tmp_path / "svc.ts").write_text(
        "export class Svc {\n  run(a: string) {\n    eval(a);\n  }\n}\n", encoding="utf-8"
    )
    (tmp_path / "svc.py").write_text(
        "class Svc:\n    def run(self, a):\n        eval(a)\n", encoding="utf-8"
    )
    ts = {"kind": "regex", "rule_id": "eval", "cwe": "CWE-95", "matched_text": "eval(a)",
          "file_path": "svc.ts", "line": 3}
    py = dict(ts, file_path="svc.py", line=3)
    occurrence.stamp_identity(tmp_path, "svc.ts", [ts])
    occurrence.stamp_identity(tmp_path, "svc.py", [py])
    assert ts["enclosing_method"] == "Svc.run(a: string)"
    assert py["enclosing_method"] == "Svc.run(self, a)"
    assert ts["identity_quality"] == py["identity_quality"] == "exact"


# --- persistence ------------------------------------------------------------

def _seed_scan(SessionLocal):
    with SessionLocal() as db:
        project = Project(name="identity-demo", default_git_url="https://github.com/org/repo.git")
        db.add(project)
        db.commit()
        scan = Scan(project_id=project.id, git_url=project.default_git_url)
        db.add(scan)
        db.commit()
        return project.id, scan.id


def test_the_writer_persists_the_occurrence_id_and_quality(occurrence, root, tmp_path):
    SessionLocal = init_db(f"sqlite:///{(tmp_path / 'ident.db').as_posix()}")
    project_id, scan_id = _seed_scan(SessionLocal)
    findings = _stamped(occurrence, root, "Orders.java", [7, 8])
    for f in findings:
        f.update(verdict="unverified", unresolved_reason="not_reviewed_regex", severity="LOW",
                 title="log injection")

    _make_findings_writer(scan_id)("Orders.java", findings)

    with SessionLocal() as db:
        rows = db.query(Finding).filter(Finding.scan_id == scan_id).order_by(Finding.line).all()
    assert [r.occurrence_id for r in rows] == _ids(findings, project_id)
    assert {r.identity_quality for r in rows} == {"exact"}


def test_a_finding_the_engine_did_not_stamp_still_gets_a_file_level_identity(tmp_path):
    SessionLocal = init_db(f"sqlite:///{(tmp_path / 'unstamped.db').as_posix()}")
    _project_id, scan_id = _seed_scan(SessionLocal)
    _make_findings_writer(scan_id)("pom.xml", [{
        "verdict": "unverified", "unresolved_reason": "not_reviewed_sca", "severity": "HIGH",
        "title": "vulnerable dependency", "kind": "sca", "rule_id": "GHSA-1", "cwe": "CWE-1",
        "matched_text": "lib@1.0", "file_path": "pom.xml",
    }])
    with SessionLocal() as db:
        row = db.query(Finding).filter(Finding.scan_id == scan_id).one()
    assert row.occurrence_id and row.identity_quality == "file_level"


def test_the_migration_adds_the_identity_columns_and_index(tmp_path):
    import sqlite3

    legacy = tmp_path / "legacy.db"
    conn = sqlite3.connect(legacy)
    conn.executescript((Path(__file__).parent / "fixtures" / "pre_dast_schema.sql").read_text())
    conn.commit()
    conn.close()
    init_db(f"sqlite:///{legacy.as_posix()}")
    conn = sqlite3.connect(legacy)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(findings)")}
    indexes = {row[1] for row in conn.execute("PRAGMA index_list(findings)")}
    legacy_row = conn.execute("SELECT occurrence_id, identity_quality FROM findings").fetchone()
    conn.close()
    assert {"occurrence_id", "identity_quality"} <= columns
    assert "ix_findings_occurrence_id" in indexes
    assert legacy_row == (None, None)


# --- version stamp ----------------------------------------------------------

def test_static_versions_for_the_mock_engine_are_fixed(tmp_path):
    scan = Scan(project_id="p", git_url="u", llm_provider="bedrock", llm_model="m")
    versions = scan_versions.static_versions(scan, mock=True)
    assert versions == {
        "engine_commit": "mock", "rule_catalog_sha256": "mock", "result_cache_version": "mock",
        "system_prompt_sha256": {}, "llm_provider": "bedrock", "llm_model": "m",
    }


def test_static_versions_for_the_real_engine_describe_the_checkout(monkeypatch):
    monkeypatch.setattr(settings, "sast_framework_path", str(_ENGINE_DIR))
    scan = Scan(project_id="p", git_url="u", llm_provider="bedrock", llm_model="m")
    versions = scan_versions.static_versions(scan, mock=False)
    assert len(versions["rule_catalog_sha256"]) == 64
    assert versions["result_cache_version"] not in ("", "mock", "unknown")
    assert versions["engine_commit"] == "unknown" or len(versions["engine_commit"]) >= 7


def test_the_rule_catalog_hash_changes_with_the_catalog(tmp_path):
    (tmp_path / "a.json").write_text("[]", encoding="utf-8")
    first = scan_versions.rule_catalog_sha256(tmp_path)
    (tmp_path / "a.json").write_text('[{"id": "x"}]', encoding="utf-8")
    assert scan_versions.rule_catalog_sha256(tmp_path) != first


def test_prompt_hashes_are_merged_from_the_usage_summary():
    merged = scan_versions.with_prompt_hashes(
        {"engine_commit": "abc", "system_prompt_sha256": {}},
        {"system_prompt_sha256": {"scan_deep_files": ["h1", "h2"]}},
    )
    assert merged["system_prompt_sha256"] == {"scan_deep_files": ["h1", "h2"]}
    assert merged["engine_commit"] == "abc"


def test_the_engine_records_system_prompt_hashes_per_step(occurrence):
    llm_client = sys.modules["llm_client"]
    usage = {}
    llm_client.record_system_prompt(usage, "scan_deep_files", "prompt A")
    llm_client.record_system_prompt(usage, "scan_deep_files", "prompt A")
    llm_client.record_system_prompt(usage, "scan_deep_files", "prompt B")
    llm_client.record_system_prompt(None, "scan_deep_files", "ignored")
    summary = llm_client.usage_cost_summary(usage)
    assert len(summary["system_prompt_sha256"]["scan_deep_files"]) == 2
