"""Unit tests for sast_engine/pipeline/sbom_scan.py.

Every deps.dev network call is mocked via unittest.mock — this module must
never touch the real network during the test suite, matching the same
mock-engine invariant the rest of the backend tests rely on.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from sast_engine.pipeline import sbom_scan


# ===========================================================================
# build_purl
# ===========================================================================


def test_build_purl_maven_splits_group_artifact():
    dep = {"ecosystem": "maven", "name": "org.springframework:spring-core", "version": "5.3.0"}
    assert sbom_scan.build_purl(dep) == "pkg:maven/org.springframework/spring-core@5.3.0"


def test_build_purl_npm_plain():
    dep = {"ecosystem": "npm", "name": "lodash", "version": "4.17.15"}
    assert sbom_scan.build_purl(dep) == "pkg:npm/lodash@4.17.15"


def test_build_purl_npm_scoped():
    dep = {"ecosystem": "npm", "name": "@angular/core", "version": "12.0.0"}
    assert sbom_scan.build_purl(dep) == "pkg:npm/%40angular/core@12.0.0"


def test_build_purl_pypi():
    dep = {"ecosystem": "pypi", "name": "requests", "version": "2.25.0"}
    assert sbom_scan.build_purl(dep) == "pkg:pypi/requests@2.25.0"


def test_build_purl_go():
    dep = {"ecosystem": "go", "name": "github.com/pkg/errors", "version": "v0.9.1"}
    assert sbom_scan.build_purl(dep) == "pkg:golang/github.com/pkg/errors@v0.9.1"


def test_build_purl_rubygems():
    dep = {"ecosystem": "rubygems", "name": "rails", "version": "6.1.0"}
    assert sbom_scan.build_purl(dep) == "pkg:gem/rails@6.1.0"


def test_build_purl_packagist():
    dep = {"ecosystem": "packagist", "name": "monolog/monolog", "version": "2.3.0"}
    assert sbom_scan.build_purl(dep) == "pkg:composer/monolog/monolog@2.3.0"


def test_build_purl_nuget():
    dep = {"ecosystem": "nuget", "name": "Newtonsoft.Json", "version": "13.0.1"}
    assert sbom_scan.build_purl(dep) == "pkg:nuget/Newtonsoft.Json@13.0.1"


def test_build_purl_cratesio():
    dep = {"ecosystem": "cratesio", "name": "serde", "version": "1.0.0"}
    assert sbom_scan.build_purl(dep) == "pkg:cargo/serde@1.0.0"


def test_build_purl_returns_none_without_version():
    dep = {"ecosystem": "pypi", "name": "requests", "version": None}
    assert sbom_scan.build_purl(dep) is None


def test_build_purl_returns_none_for_unknown_ecosystem():
    dep = {"ecosystem": "unknown-eco", "name": "foo", "version": "1.0.0"}
    assert sbom_scan.build_purl(dep) is None


# ===========================================================================
# lookup_depsdev_license — network mocked
# ===========================================================================


def test_lookup_depsdev_license_returns_spdx_id():
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.json.return_value = {
        "version": {"licenseDetails": [{"spdx": "Apache-2.0", "license": "Apache-2.0"}]}
    }
    with patch.object(sbom_scan.requests, "get", return_value=fake_response):
        result = sbom_scan.lookup_depsdev_license("pkg:pypi/requests@2.25.0")
    assert result == {"spdx_id": "Apache-2.0", "raw_license": "Apache-2.0"}


def test_lookup_depsdev_license_falls_back_to_plain_licenses_field():
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.json.return_value = {"version": {"licenses": ["MIT"]}}
    with patch.object(sbom_scan.requests, "get", return_value=fake_response):
        result = sbom_scan.lookup_depsdev_license("pkg:npm/lodash@4.17.15")
    assert result == {"spdx_id": "MIT", "raw_license": "MIT"}


def test_lookup_depsdev_license_returns_none_on_404():
    fake_response = MagicMock()
    fake_response.status_code = 404
    with patch.object(sbom_scan.requests, "get", return_value=fake_response):
        assert sbom_scan.lookup_depsdev_license("pkg:pypi/requests@2.25.0") is None


def test_lookup_depsdev_license_returns_none_for_unsupported_ecosystem():
    with patch.object(sbom_scan.requests, "get") as mock_get:
        result = sbom_scan.lookup_depsdev_license("pkg:gem/rails@6.1.0")
    assert result is None
    mock_get.assert_not_called()


def test_lookup_depsdev_license_swallows_request_errors():
    with patch.object(sbom_scan.requests, "get", side_effect=sbom_scan.requests.RequestException("boom")):
        assert sbom_scan.lookup_depsdev_license("pkg:pypi/requests@2.25.0") is None


# ===========================================================================
# classify_license
# ===========================================================================


def test_classify_license_known_spdx_permissive_is_fully_free():
    dep = {"name": "requests"}
    result = sbom_scan.classify_license(dep, {"spdx_id": "Apache-2.0"})
    assert result["spdx_id"] == "Apache-2.0"
    assert result["license_type"] == "permissive"
    assert result["cost_classification"] == "fully_free"


def test_classify_license_aliased_license_string_resolves():
    dep = {"name": "some-pkg"}
    result = sbom_scan.classify_license(dep, {"spdx_id": "MIT License"})
    assert result["spdx_id"] == "MIT"
    assert result["cost_classification"] == "fully_free"


def test_classify_license_unknown_when_no_result():
    dep = {"name": "totally-unknown-pkg"}
    result = sbom_scan.classify_license(dep, None)
    assert result["spdx_id"] == "LicenseRef-unknown"
    assert result["cost_classification"] == "unknown"


def test_classify_license_vendor_edition_hit_is_partially_free():
    # "redis" is ported from the reference app's community/enterprise table
    # with non-empty paid_features.
    dep = {"name": "redis"}
    result = sbom_scan.classify_license(dep, {"spdx_id": "BSD-3-Clause"})
    assert result["vendor"] == "Redis Ltd."
    assert result["cost_classification"] == "partially_free"


def test_classify_license_copyleft_is_partially_free():
    dep = {"name": "some-gpl-pkg"}
    result = sbom_scan.classify_license(dep, {"spdx_id": "GPL-3.0-only"})
    assert result["license_type"] == "copyleft"
    assert result["cost_classification"] == "partially_free"


# ===========================================================================
# build_components / build_cyclonedx_sbom / build_spdx_sbom
# ===========================================================================


def _sample_components():
    deps = [
        {
            "ecosystem": "maven",
            "name": "org.springframework:spring-core",
            "version": "5.3.0",
            "scope": "runtime",
            "source_file": "pom.xml",
        },
        {
            "ecosystem": "pypi",
            "name": "requests",
            "version": "2.25.0",
            "scope": "runtime",
            "source_file": "requirements.txt",
        },
    ]
    license_by_purl = {
        "pkg:maven/org.springframework/spring-core@5.3.0": {
            "spdx_id": "Apache-2.0",
            "license_name": "Apache License 2.0",
            "license_type": "permissive",
            "vendor": None,
            "cost_classification": "fully_free",
        },
        "pkg:pypi/requests@2.25.0": {
            "spdx_id": "Apache-2.0",
            "license_name": "Apache License 2.0",
            "license_type": "permissive",
            "vendor": None,
            "cost_classification": "fully_free",
        },
    }
    return sbom_scan.build_components(deps, license_by_purl)


def test_build_components_shape():
    components = _sample_components()
    assert len(components) == 2
    maven_comp = next(c for c in components if c["ecosystem"] == "maven")
    assert maven_comp["group"] == "org.springframework"
    assert maven_comp["name"] == "spring-core"
    assert maven_comp["direct"] is True
    assert maven_comp["licenses"] == [{"spdx_id": "Apache-2.0", "name": "Apache License 2.0"}]
    assert maven_comp["cost_classification"] == "fully_free"
    assert maven_comp["origin_type"] == "Open Source"
    assert maven_comp["dependency_relationship"] == "Direct"


def test_default_origin_type_proprietary_vs_open_source():
    assert sbom_scan._default_origin_type("proprietary") == "Proprietary"
    assert sbom_scan._default_origin_type("permissive") == "Open Source"
    assert sbom_scan._default_origin_type("unknown") == "Open Source"


def test_dependency_relationship_label_by_scope():
    assert sbom_scan._dependency_relationship_label("runtime") == "Direct"
    assert sbom_scan._dependency_relationship_label(None) == "Direct"
    assert sbom_scan._dependency_relationship_label("dev") == "Direct (Dev)"
    assert sbom_scan._dependency_relationship_label("peer") == "Direct (Peer)"
    assert sbom_scan._dependency_relationship_label("provided") == "Direct (Provided)"


# ===========================================================================
# llm_enrich_components — Bedrock Claude Haiku enrichment, network mocked
# ===========================================================================


def test_llm_enrich_components_fills_unresolved_supplier_and_license():
    components = [
        {
            "name": "some-unknown-pkg",
            "group": None,
            "ecosystem": "npm",
            "version": "1.0.0",
            "licenses": [],
            "cost_classification": "unknown",
            "vendor": None,
            "origin_type": "Open Source",
        }
    ]
    fake_llm_client = MagicMock()
    fake_llm_client.call_llm.return_value = "{}"
    fake_llm_client.parse_llm_json_dict.return_value = (
        {"components": [{"index": 0, "license": "MIT", "supplier": "Acme Corp", "type": "Open Source"}]},
        None,
    )
    with patch.object(sbom_scan, "_get_llm_client", return_value=fake_llm_client):
        sbom_scan.llm_enrich_components(components)

    comp = components[0]
    assert comp["vendor"] == "Acme Corp"
    assert comp["licenses"][0]["spdx_id"] == "MIT"
    assert comp["llm_enriched"] is True


def test_llm_enrich_components_skips_components_that_already_have_data():
    components = [
        {
            "name": "requests",
            "group": None,
            "ecosystem": "pypi",
            "version": "2.25.0",
            "licenses": [{"spdx_id": "Apache-2.0", "name": "Apache License 2.0"}],
            "cost_classification": "fully_free",
            "vendor": "Python Software Foundation",
            "origin_type": "Open Source",
        }
    ]
    fake_llm_client = MagicMock()
    with patch.object(sbom_scan, "_get_llm_client", return_value=fake_llm_client):
        sbom_scan.llm_enrich_components(components)
    fake_llm_client.call_llm.assert_not_called()


def test_llm_enrich_components_swallows_llm_failures():
    components = [
        {
            "name": "some-unknown-pkg",
            "group": None,
            "ecosystem": "npm",
            "version": "1.0.0",
            "licenses": [],
            "cost_classification": "unknown",
            "vendor": None,
            "origin_type": "Open Source",
        }
    ]
    fake_llm_client = MagicMock()
    fake_llm_client.call_llm.side_effect = RuntimeError("bedrock unavailable")
    with patch.object(sbom_scan, "_get_llm_client", return_value=fake_llm_client):
        sbom_scan.llm_enrich_components(components)  # must not raise
    assert components[0]["vendor"] is None


def test_llm_enrich_components_noop_when_llm_client_unavailable():
    components = [
        {
            "name": "some-unknown-pkg",
            "group": None,
            "ecosystem": "npm",
            "version": "1.0.0",
            "licenses": [],
            "cost_classification": "unknown",
            "vendor": None,
            "origin_type": "Open Source",
        }
    ]
    with patch.object(sbom_scan, "_get_llm_client", side_effect=ImportError("boto3 missing")):
        sbom_scan.llm_enrich_components(components)  # must not raise
    assert components[0]["vendor"] is None


def test_build_cyclonedx_sbom_shape():
    components = _sample_components()
    sbom = sbom_scan.build_cyclonedx_sbom(components, "scan-123")
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert sbom["serialNumber"] == "urn:uuid:scan-123"
    assert len(sbom["components"]) == 2
    assert sbom["metadata"]["component"]["type"] == "application"
    root_ref = sbom["metadata"]["component"]["bom-ref"]
    deps_entry = sbom["dependencies"][0]
    assert deps_entry["ref"] == root_ref
    assert len(deps_entry["dependsOn"]) == 2


def test_build_spdx_sbom_shape():
    components = _sample_components()
    spdx = sbom_scan.build_spdx_sbom(components, "scan-123")
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert spdx["SPDXID"] == "SPDXRef-DOCUMENT"
    # root package + 2 components
    assert len(spdx["packages"]) == 3
    contains_rels = [r for r in spdx["relationships"] if r["relationshipType"] == "CONTAINS"]
    assert len(contains_rels) == 2
    describes_rels = [r for r in spdx["relationships"] if r["relationshipType"] == "DESCRIBES"]
    assert len(describes_rels) == 1


# ===========================================================================
# run_sbom_scan orchestration
# ===========================================================================


def test_run_sbom_scan_calls_discovery_writer(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests==2.25.0\n", encoding="utf-8")

    written_discovery: list[dict] = []

    with patch.object(
        sbom_scan, "lookup_depsdev_license", return_value={"spdx_id": "Apache-2.0"}
    ):
        result = sbom_scan.run_sbom_scan(
            tmp_path,
            scan_id="scan-abc",
            discovery_writer=lambda discovery: written_discovery.append(discovery),
        )

    assert len(written_discovery) == 1
    summary = result["discovery"]["component_summary"]
    assert summary["total_components"] == 1
    assert summary["ecosystems"] == ["pypi"]
    assert summary["license_summary"]["fully_free"] == 1
    assert result["discovery"]["sbom_cyclonedx"]["serialNumber"] == "urn:uuid:scan-abc"
    assert result["discovery"]["sbom_spdx"]["name"] == "SBOM-scan-abc"


def test_run_sbom_scan_with_no_dependencies(tmp_path: Path):
    result = sbom_scan.run_sbom_scan(tmp_path)
    assert result["discovery"]["component_summary"]["total_components"] == 0
    assert result["discovery"]["sbom_cyclonedx"] is None
    assert result["discovery"]["sbom_spdx"] is None


def test_run_sbom_scan_llm_enrichment_disabled_by_default(tmp_path: Path):
    """The default (use_llm_enrichment=False) must never touch the LLM
    client — every other test in this module relies on that invariant."""
    (tmp_path / "requirements.txt").write_text("requests==2.25.0\n", encoding="utf-8")
    with patch.object(sbom_scan, "_get_llm_client") as mock_get_client:
        with patch.object(sbom_scan, "lookup_depsdev_license", return_value=None):
            result = sbom_scan.run_sbom_scan(tmp_path)
    mock_get_client.assert_not_called()
    assert "llm_enrichment_usage" not in result["discovery"]


def test_run_sbom_scan_llm_enrichment_enabled_populates_usage(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests==2.25.0\n", encoding="utf-8")
    fake_llm_client = MagicMock()
    fake_llm_client.init_usage.return_value = {"cost_usd": 0.0}
    fake_llm_client.call_llm.return_value = "{}"
    fake_llm_client.parse_llm_json_dict.return_value = (
        {"components": [{"index": 0, "license": "Apache-2.0", "supplier": "Python Software Foundation", "type": "Open Source"}]},
        None,
    )
    fake_llm_client.usage_cost_summary.return_value = {"cost_usd": 0.0001, "provider": "bedrock"}
    with patch.object(sbom_scan, "_get_llm_client", return_value=fake_llm_client):
        with patch.object(sbom_scan, "lookup_depsdev_license", return_value=None):
            result = sbom_scan.run_sbom_scan(tmp_path, use_llm_enrichment=True)
    assert result["discovery"]["llm_enrichment_usage"] == {"cost_usd": 0.0001, "provider": "bedrock"}
    comp = result["discovery"]["components"][0]
    # "requests" already has a static vendor entry ("Kenneth Reitz") — the LLM
    # is only consulted because the license was otherwise unresolved, and its
    # answer never overwrites an already-known vendor (see _apply_llm_enrichment).
    assert comp["vendor"] == "Kenneth Reitz"
    assert comp["licenses"][0]["spdx_id"] == "Apache-2.0"
