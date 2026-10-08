"""Unit tests for sast_engine/pipeline/sca_scan.py.

Every OSV.dev network call is mocked via unittest.mock — this module must
never touch the real network during the test suite, matching the same
mock-engine invariant the rest of the backend tests rely on.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sast_engine.pipeline import sca_scan


# ===========================================================================
# collect_dependencies
# ===========================================================================


def test_collect_dependencies_parses_requirements_txt(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests==2.25.0\nflask>=1.1.0\n", encoding="utf-8")

    deps = sca_scan.collect_dependencies(tmp_path)

    by_name = {d["name"]: d for d in deps}
    assert by_name["requests"]["ecosystem"] == "pypi"
    assert by_name["requests"]["version"] == "==2.25.0"
    assert by_name["requests"]["source_file"] == "requirements.txt"
    assert "flask" in by_name


def test_collect_dependencies_parses_package_json(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"lodash": "4.17.15"}, "devDependencies": {"jest": "^29.0.0"}}',
        encoding="utf-8",
    )

    deps = sca_scan.collect_dependencies(tmp_path)

    by_name = {d["name"]: d for d in deps}
    assert by_name["lodash"]["ecosystem"] == "npm"
    assert by_name["lodash"]["version"] == "4.17.15"
    assert by_name["jest"]["scope"] == "dev"


def test_collect_dependencies_parses_pom_xml(tmp_path: Path):
    (tmp_path / "pom.xml").write_text(
        """<project>
  <properties><spring.version>5.3.0</spring.version></properties>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>${spring.version}</version>
    </dependency>
  </dependencies>
</project>""",
        encoding="utf-8",
    )

    deps = sca_scan.collect_dependencies(tmp_path)

    assert len(deps) == 1
    assert deps[0]["ecosystem"] == "maven"
    assert deps[0]["name"] == "org.springframework:spring-core"
    assert deps[0]["version"] == "5.3.0"
    assert deps[0]["source_file"] == "pom.xml"


def test_collect_dependencies_dedupes_identical_entries(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests==2.25.0\n", encoding="utf-8")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "requirements.txt").write_text("requests==2.25.0\n", encoding="utf-8")

    deps = sca_scan.collect_dependencies(tmp_path)
    matching = [d for d in deps if d["name"] == "requests"]
    assert len(matching) == 1


def test_collect_dependencies_skips_vendored_directories(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests==2.25.0\n", encoding="utf-8")
    vendored = tmp_path / "node_modules" / "some-pkg"
    vendored.mkdir(parents=True)
    (vendored / "package.json").write_text('{"dependencies": {"left-pad": "1.0.0"}}', encoding="utf-8")

    deps = sca_scan.collect_dependencies(tmp_path)
    assert all(d["name"] != "left-pad" for d in deps)


def test_collect_dependencies_ignores_unparseable_manifest(tmp_path: Path):
    (tmp_path / "package.json").write_text("{not valid json", encoding="utf-8")
    deps = sca_scan.collect_dependencies(tmp_path)
    assert deps == []


# ===========================================================================
# OSV query construction / cleanup
# ===========================================================================


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("2.25.0", "2.25.0"),
        ("^1.2.3", "1.2.3"),
        ("~1.2.0", "1.2.0"),
        (">=1.0.0,<2.0.0", "1.0.0"),
        ("==2.25.0", "2.25.0"),
        (None, None),
    ],
)
def test_clean_version(raw, expected):
    assert sca_scan._clean_version(raw) == expected


def test_build_osv_query_maps_ecosystem():
    dep = {"ecosystem": "pypi", "name": "requests", "version": "2.25.0"}
    query = sca_scan.build_osv_query(dep)
    assert query == {"version": "2.25.0", "package": {"name": "requests", "ecosystem": "PyPI"}}


def test_build_osv_query_returns_none_for_unknown_ecosystem():
    dep = {"ecosystem": "unknown-eco", "name": "foo", "version": "1.0.0"}
    assert sca_scan.build_osv_query(dep) is None


def test_build_osv_query_returns_none_without_version():
    dep = {"ecosystem": "npm", "name": "foo", "version": None}
    assert sca_scan.build_osv_query(dep) is None


# ===========================================================================
# query_osv_batch — network mocked
# ===========================================================================


def test_query_osv_batch_returns_hits_by_index():
    deps = [
        {"ecosystem": "pypi", "name": "requests", "version": "2.25.0"},
        {"ecosystem": "pypi", "name": "safe-pkg", "version": "1.0.0"},
    ]
    fake_response = MagicMock()
    fake_response.json.return_value = {
        "results": [
            {"vulns": [{"id": "GHSA-xxxx"}]},
            {"vulns": []},
        ]
    }
    fake_response.raise_for_status.return_value = None

    with patch.object(sca_scan.requests, "post", return_value=fake_response) as mock_post:
        hits = sca_scan.query_osv_batch(deps)

    assert hits == {0: [{"id": "GHSA-xxxx"}]}
    mock_post.assert_called_once()


def test_query_osv_batch_skips_unqueryable_dependencies():
    deps = [{"ecosystem": "unknown", "name": "foo", "version": "1.0.0"}]
    with patch.object(sca_scan.requests, "post") as mock_post:
        hits = sca_scan.query_osv_batch(deps)
    assert hits == {}
    mock_post.assert_not_called()


def test_query_osv_batch_swallows_request_errors():
    deps = [{"ecosystem": "pypi", "name": "requests", "version": "2.25.0"}]
    with patch.object(sca_scan.requests, "post", side_effect=sca_scan.requests.RequestException("boom")):
        hits = sca_scan.query_osv_batch(deps)
    assert hits == {}


def test_get_full_osv_vulnerability_returns_none_on_404():
    fake_response = MagicMock()
    fake_response.status_code = 404
    with patch.object(sca_scan.requests, "get", return_value=fake_response):
        assert sca_scan.get_full_osv_vulnerability("GHSA-xxxx") is None


def test_get_full_osv_vulnerability_returns_json_body():
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.json.return_value = {"id": "GHSA-xxxx", "summary": "test"}
    fake_response.raise_for_status.return_value = None
    with patch.object(sca_scan.requests, "get", return_value=fake_response):
        result = sca_scan.get_full_osv_vulnerability("GHSA-xxxx")
    assert result == {"id": "GHSA-xxxx", "summary": "test"}


# ===========================================================================
# Severity / CVE / fixed-version extraction
# ===========================================================================


def test_extract_cve_from_vulnerability_prefers_direct_id():
    assert sca_scan.extract_cve_from_vulnerability({"id": "CVE-2021-1234"}) == "CVE-2021-1234"


def test_extract_cve_from_vulnerability_falls_back_to_alias():
    vuln = {"id": "GHSA-xxxx", "aliases": ["CVE-2021-9999"]}
    assert sca_scan.extract_cve_from_vulnerability(vuln) == "CVE-2021-9999"


def test_extract_cve_from_vulnerability_returns_none_when_absent():
    assert sca_scan.extract_cve_from_vulnerability({"id": "GHSA-xxxx"}) is None


def test_extract_fixed_versions_dedupes_and_orders():
    vuln = {
        "affected": [
            {"ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.4"}]}]},
            {"ranges": [{"events": [{"fixed": "1.2.4"}, {"fixed": "1.3.0"}]}]},
        ]
    }
    assert sca_scan.extract_fixed_versions(vuln) == ["1.2.4", "1.3.0"]


def test_cvss3_base_score_known_critical_vector():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert sca_scan._cvss3_base_score(vector) == 9.8


def test_cvss3_base_score_returns_none_for_non_v3_vector():
    assert sca_scan._cvss3_base_score("AV:N/AC:L/Au:N/C:C/I:C/A:C") is None
    assert sca_scan._cvss3_base_score("") is None


def test_extract_cvss_score_prefers_vector_parse():
    vuln = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    score, source = sca_scan.extract_cvss_score(vuln)
    assert score == 9.8
    assert source == "CVSS_V3"


def test_extract_cvss_score_returns_none_when_absent():
    score, source = sca_scan.extract_cvss_score({})
    assert score is None
    assert source == "none"


def test_get_severity_uses_database_specific_label():
    assert sca_scan.get_severity(None, {"severity": "MODERATE"}) == "MEDIUM"
    assert sca_scan.get_severity(None, {"severity": "CRITICAL"}) == "CRITICAL"


def test_get_severity_falls_back_to_cvss_thresholds():
    assert sca_scan.get_severity(9.5) == "CRITICAL"
    assert sca_scan.get_severity(7.5) == "HIGH"
    assert sca_scan.get_severity(5.0) == "MEDIUM"
    assert sca_scan.get_severity(1.0) == "LOW"
    assert sca_scan.get_severity(None) == "UNKNOWN"


# ===========================================================================
# build_findings — end to end with OSV mocked
# ===========================================================================


def test_build_findings_shape():
    deps = [{"ecosystem": "pypi", "name": "requests", "version": "2.25.0", "source_file": "requirements.txt"}]

    with patch.object(sca_scan, "query_osv_batch", return_value={0: [{"id": "CVE-2021-1234"}]}), patch.object(
        sca_scan,
        "get_full_osv_vulnerability",
        return_value={
            "id": "CVE-2021-1234",
            "summary": "A test vulnerability",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "affected": [{"ranges": [{"events": [{"fixed": "2.26.0"}]}]}],
        },
    ):
        findings = sca_scan.build_findings(deps)

    assert len(findings) == 1
    f = findings[0]
    assert f["kind"] == "sca"
    assert f["verdict"] == "unverified"
    assert f["severity"] == "CRITICAL"
    assert f["cvss"] == 9.8
    assert f["rule_id"] == "CVE-2021-1234"
    assert f["matched_text"] == "requests@2.25.0"
    assert f["file_path"] == "requirements.txt"
    assert "2.26.0" in f["ai_fix"]
    assert "A test vulnerability" in f["title"]


def test_build_findings_no_fixed_version_uses_generic_ai_fix():
    deps = [{"ecosystem": "pypi", "name": "requests", "version": "2.25.0", "source_file": "requirements.txt"}]

    with patch.object(sca_scan, "query_osv_batch", return_value={0: [{"id": "GHSA-xxxx"}]}), patch.object(
        sca_scan, "get_full_osv_vulnerability", return_value={"id": "GHSA-xxxx"}
    ):
        findings = sca_scan.build_findings(deps)

    assert len(findings) == 1
    assert "No fixed version" in findings[0]["ai_fix"]
    assert findings[0]["severity"] == "UNKNOWN"


def test_build_findings_sorted_by_severity():
    deps = [
        {"ecosystem": "pypi", "name": "pkg-a", "version": "1.0.0", "source_file": "requirements.txt"},
        {"ecosystem": "pypi", "name": "pkg-b", "version": "1.0.0", "source_file": "requirements.txt"},
    ]

    def fake_detail(vuln_id):
        if vuln_id == "LOW-1":
            return {"id": "LOW-1", "database_specific": {"severity": "LOW"}}
        return {"id": "CRIT-1", "database_specific": {"severity": "CRITICAL"}}

    with patch.object(
        sca_scan, "query_osv_batch", return_value={0: [{"id": "LOW-1"}], 1: [{"id": "CRIT-1"}]}
    ), patch.object(sca_scan, "get_full_osv_vulnerability", side_effect=fake_detail):
        findings = sca_scan.build_findings(deps)

    assert [f["severity"] for f in findings] == ["CRITICAL", "LOW"]


def test_build_findings_returns_empty_list_when_no_hits():
    deps = [{"ecosystem": "pypi", "name": "safe-pkg", "version": "1.0.0", "source_file": "requirements.txt"}]
    with patch.object(sca_scan, "query_osv_batch", return_value={}):
        assert sca_scan.build_findings(deps) == []


# ===========================================================================
# run_sca_scan orchestration
# ===========================================================================


def test_run_sca_scan_calls_writers_and_returns_discovery(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests==2.25.0\n", encoding="utf-8")

    written_findings: list[tuple[str, list[dict]]] = []
    written_discovery: list[dict] = []

    with patch.object(sca_scan, "query_osv_batch", return_value={0: [{"id": "CVE-2021-1234"}]}), patch.object(
        sca_scan,
        "get_full_osv_vulnerability",
        return_value={"id": "CVE-2021-1234", "database_specific": {"severity": "HIGH"}},
    ):
        result = sca_scan.run_sca_scan(
            tmp_path,
            findings_writer=lambda path, findings: written_findings.append((path, findings)),
            discovery_writer=lambda discovery: written_discovery.append(discovery),
        )

    assert len(written_findings) == 1
    assert written_findings[0][0] == "requirements.txt"
    assert len(written_findings[0][1]) == 1
    assert len(written_discovery) == 1
    summary = result["discovery"]["dependency_summary"]
    assert summary["total_dependencies"] == 1
    assert summary["vulnerable_dependencies"] == 1
    assert summary["severity_counts"]["HIGH"] == 1
    assert result["usage_summary"] is None


def test_run_sca_scan_with_no_dependencies(tmp_path: Path):
    result = sca_scan.run_sca_scan(tmp_path)
    assert result["discovery"]["dependency_summary"]["total_dependencies"] == 0
    assert result["discovery"]["dependency_summary"]["vulnerable_dependencies"] == 0
