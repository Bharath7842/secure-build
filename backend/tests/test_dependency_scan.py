"""Coverage for the dependency-manifest evidence pass
(backend/sast_engine/pipeline/dependency_scan.py) — orchestrates manifest
parsing + signature matching + config-file corroboration into the
tech-stack evidence node_analyze_tech_stack consumes.
"""

from pathlib import Path

import pytest

pytest.importorskip("langgraph")

from app.config import settings  # noqa: E402
from app.services.agent_bridge import _load_agent_module  # noqa: E402


@pytest.fixture()
def agent(monkeypatch):
    import sys

    engine_dir = Path(__file__).resolve().parents[1] / "sast_engine"
    monkeypatch.setattr(settings, "sast_framework_path", str(engine_dir))
    sys.modules.pop("sast_scan_agent", None)
    return _load_agent_module()


@pytest.fixture()
def dependency_scan(agent):
    import sys

    return sys.modules["pipeline.dependency_scan"]


def _scan_for(agent, root):
    state = {
        "local_path": str(root),
        "scope": None,
        "context_note": "",
        "verbose": False,
        "verbose_files": False,
        "use_llm": False,
        "persist_to_disk": False,
        "_tracer": agent.AgentTrace(verbose=False),
    }
    return agent.node_scan_directory(state)["scan"]


def test_analyze_dependencies_returns_none_without_manifests(agent, dependency_scan, tmp_path):
    (tmp_path / "readme.txt").write_text("hi\n", encoding="utf-8")
    scan = _scan_for(agent, tmp_path)
    assert dependency_scan.analyze_dependencies(scan, tmp_path) is None


def test_analyze_dependencies_recognizes_non_spring_java_stack(agent, dependency_scan, tmp_path):
    """The reported bug's exact shape: a legacy Java EE project with real
    JAX-RS/EJB/Axis2 dependencies but zero Spring annotations — the
    dependency-manifest scan is what makes this recognizable at all, since
    ast_struct.py's tree-sitter pass only knows Spring stereotypes."""
    pom = """
    <project>
      <dependencies>
        <dependency>
          <groupId>org.jboss.resteasy</groupId>
          <artifactId>resteasy-jaxrs</artifactId>
          <version>3.15.0.Final</version>
        </dependency>
        <dependency>
          <groupId>javax.ejb</groupId>
          <artifactId>javax.ejb-api</artifactId>
          <version>3.2</version>
        </dependency>
        <dependency>
          <groupId>org.apache.axis2</groupId>
          <artifactId>axis2-kernel</artifactId>
          <version>1.7.9</version>
        </dependency>
      </dependencies>
    </project>
    """
    (tmp_path / "pom.xml").write_text(pom, encoding="utf-8")
    web_inf = tmp_path / "src/main/webapp/WEB-INF"
    web_inf.mkdir(parents=True)
    (web_inf / "web.xml").write_text("<web-app/>\n", encoding="utf-8")

    scan = _scan_for(agent, tmp_path)
    summary = dependency_scan.analyze_dependencies(scan, tmp_path)

    assert summary is not None
    assert summary["manifests_parsed"] == ["pom.xml"]
    labels = {f["label"] for f in summary["frameworks"]}
    assert labels == {"JBoss RESTEasy (JAX-RS)", "EJB", "Apache Axis2 SOAP"}
    assert any("Java EE deployment descriptor" in e for e in summary["config_evidence"])


def test_analyze_dependencies_struts_config_corroboration(agent, dependency_scan, tmp_path):
    pom = """
    <project>
      <dependencies>
        <dependency>
          <groupId>org.apache.struts</groupId>
          <artifactId>struts-core</artifactId>
          <version>1.3.10</version>
        </dependency>
      </dependencies>
    </project>
    """
    (tmp_path / "pom.xml").write_text(pom, encoding="utf-8")
    (tmp_path / "struts-config.xml").write_text("<struts-config/>\n", encoding="utf-8")

    scan = _scan_for(agent, tmp_path)
    summary = dependency_scan.analyze_dependencies(scan, tmp_path)
    assert any("Struts XML routing config" in e for e in summary["config_evidence"])


def test_analyze_dependencies_no_corroboration_without_config_file(agent, dependency_scan, tmp_path):
    pom = """
    <project>
      <dependencies>
        <dependency>
          <groupId>org.apache.struts</groupId>
          <artifactId>struts-core</artifactId>
          <version>1.3.10</version>
        </dependency>
      </dependencies>
    </project>
    """
    (tmp_path / "pom.xml").write_text(pom, encoding="utf-8")

    scan = _scan_for(agent, tmp_path)
    summary = dependency_scan.analyze_dependencies(scan, tmp_path)
    assert summary["config_evidence"] == []


def test_analyze_dependencies_unrecognized_not_silently_dropped(agent, dependency_scan, tmp_path):
    pom = """
    <project>
      <dependencies>
        <dependency>
          <groupId>com.example</groupId>
          <artifactId>totally-unknown-widget</artifactId>
          <version>1.0</version>
        </dependency>
      </dependencies>
    </project>
    """
    (tmp_path / "pom.xml").write_text(pom, encoding="utf-8")
    scan = _scan_for(agent, tmp_path)
    summary = dependency_scan.analyze_dependencies(scan, tmp_path)
    assert summary["frameworks"] == []
    assert summary["unrecognized_count"] == 1
    assert "maven:com.example:totally-unknown-widget" in summary["unrecognized_sample"]
    # the full list is kept (not just count + 20 samples) so it can be classified
    assert summary["unrecognized_dependencies"] == [
        {"ecosystem": "maven", "name": "com.example:totally-unknown-widget", "version": "1.0"}
    ]


def test_analyze_dependencies_multi_module_property_resolution(agent, dependency_scan, tmp_path):
    """A child module's ${property} resolves against a parent pom's
    <properties>, found elsewhere in the same repo walk (best-effort
    multi-module support, not full Maven inheritance)."""
    parent_pom = """
    <project>
      <properties>
        <resteasy.version>3.15.0.Final</resteasy.version>
      </properties>
    </project>
    """
    (tmp_path / "pom.xml").write_text(parent_pom, encoding="utf-8")

    child_dir = tmp_path / "module-a"
    child_dir.mkdir()
    child_pom = """
    <project>
      <dependencies>
        <dependency>
          <groupId>org.jboss.resteasy</groupId>
          <artifactId>resteasy-jaxrs</artifactId>
          <version>${resteasy.version}</version>
        </dependency>
      </dependencies>
    </project>
    """
    (child_dir / "pom.xml").write_text(child_pom, encoding="utf-8")

    scan = _scan_for(agent, tmp_path)
    summary = dependency_scan.analyze_dependencies(scan, tmp_path)
    assert "module-a/pom.xml" in summary["manifests_parsed"]
    resteasy = next(f for f in summary["frameworks"] if f["label"] == "JBoss RESTEasy (JAX-RS)")
    assert resteasy["matched_dependencies"][0]["version"] == "3.15.0.Final"
