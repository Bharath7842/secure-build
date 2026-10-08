"""Coverage for per-ecosystem dependency-manifest parsers
(backend/sast_engine/pipeline/manifest_parsers.py) — pure parsing, no LLM,
no filesystem access, no SAST agent state involved.
"""

from pathlib import Path

import pytest

pytest.importorskip("langgraph")

from app.config import settings  # noqa: E402
from app.services.agent_bridge import _load_agent_module  # noqa: E402


@pytest.fixture()
def manifest_parsers(monkeypatch):
    import sys

    engine_dir = Path(__file__).resolve().parents[1] / "sast_engine"
    monkeypatch.setattr(settings, "sast_framework_path", str(engine_dir))
    sys.modules.pop("sast_scan_agent", None)
    _load_agent_module()
    return sys.modules["pipeline.manifest_parsers"]


# ---------------------------------------------------------------------------
# Maven — pom.xml
# ---------------------------------------------------------------------------


def test_parse_pom_xml_direct_dependencies(manifest_parsers):
    text = """
    <project>
      <dependencies>
        <dependency>
          <groupId>org.jboss.resteasy</groupId>
          <artifactId>resteasy-jaxrs</artifactId>
          <version>3.15.0.Final</version>
        </dependency>
        <dependency>
          <groupId>junit</groupId>
          <artifactId>junit</artifactId>
          <version>4.13.2</version>
          <scope>test</scope>
        </dependency>
      </dependencies>
    </project>
    """
    deps = manifest_parsers.parse_pom_xml(text)
    assert len(deps) == 2
    by_name = {d["name"]: d for d in deps}
    assert by_name["org.jboss.resteasy:resteasy-jaxrs"]["version"] == "3.15.0.Final"
    assert by_name["junit:junit"]["scope"] == "test"


def test_parse_pom_xml_resolves_own_properties(manifest_parsers):
    text = """
    <project>
      <properties>
        <resteasy.version>3.15.0.Final</resteasy.version>
      </properties>
      <dependencies>
        <dependency>
          <groupId>org.jboss.resteasy</groupId>
          <artifactId>resteasy-jaxrs</artifactId>
          <version>${resteasy.version}</version>
        </dependency>
      </dependencies>
    </project>
    """
    deps = manifest_parsers.parse_pom_xml(text)
    assert deps[0]["version"] == "3.15.0.Final"


def test_parse_pom_xml_resolves_externally_supplied_properties(manifest_parsers):
    """A child module's placeholder resolves against a parent pom's
    <properties>, supplied by the caller — multi-module property lookup."""
    child = """
    <project>
      <dependencies>
        <dependency>
          <groupId>org.apache.axis2</groupId>
          <artifactId>axis2-kernel</artifactId>
          <version>${axis2.version}</version>
        </dependency>
      </dependencies>
    </project>
    """
    deps = manifest_parsers.parse_pom_xml(child, properties={"axis2.version": "1.7.9"})
    assert deps[0]["version"] == "1.7.9"


def test_parse_pom_xml_unresolved_placeholder_kept_as_literal(manifest_parsers):
    text = """
    <project>
      <dependencies>
        <dependency>
          <groupId>com.example</groupId>
          <artifactId>widget</artifactId>
          <version>${unknown.version}</version>
        </dependency>
      </dependencies>
    </project>
    """
    deps = manifest_parsers.parse_pom_xml(text)
    assert deps[0]["version"] == "${unknown.version}"


def test_parse_pom_xml_malformed_returns_empty(manifest_parsers):
    assert manifest_parsers.parse_pom_xml("<project><dependencies>") == []


def test_extract_pom_properties(manifest_parsers):
    text = "<project><properties><foo.version>1.2.3</foo.version></properties></project>"
    assert manifest_parsers.extract_pom_properties(text) == {"foo.version": "1.2.3"}


# ---------------------------------------------------------------------------
# Gradle
# ---------------------------------------------------------------------------


def test_parse_gradle_extracts_coordinates(manifest_parsers):
    text = """
    dependencies {
        implementation 'org.springframework.boot:spring-boot-starter-web:3.2.0'
        testImplementation "junit:junit:4.13.2"
    }
    """
    deps = manifest_parsers.parse_gradle(text)
    names = {d["name"] for d in deps}
    assert names == {"org.springframework.boot:spring-boot-starter-web", "junit:junit"}


# ---------------------------------------------------------------------------
# npm — package.json
# ---------------------------------------------------------------------------


def test_parse_package_json_dependencies_and_dev(manifest_parsers):
    text = """
    {
      "dependencies": {"express": "^4.18.0"},
      "devDependencies": {"jest": "^29.0.0"}
    }
    """
    deps = manifest_parsers.parse_package_json(text)
    by_name = {d["name"]: d for d in deps}
    assert by_name["express"]["scope"] == "runtime"
    assert by_name["jest"]["scope"] == "dev"


def test_parse_package_json_malformed_returns_empty(manifest_parsers):
    assert manifest_parsers.parse_package_json("{not json") == []


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------


def test_parse_requirements_txt(manifest_parsers):
    text = """
# a comment
flask==3.0.0
requests>=2.31,<3
-r other.txt
django
"""
    deps = manifest_parsers.parse_requirements_txt(text)
    by_name = {d["name"]: d for d in deps}
    assert by_name["flask"]["version"] == "==3.0.0"
    assert by_name["requests"]["version"] == ">=2.31,<3"
    assert by_name["django"]["version"] is None
    assert "other.txt" not in by_name


def test_parse_pyproject_toml_pep621(manifest_parsers):
    text = """
[project]
name = "demo"
dependencies = ["fastapi>=0.100", "sqlalchemy"]
"""
    deps = manifest_parsers.parse_pyproject_toml(text)
    names = {d["name"] for d in deps}
    assert names == {"fastapi", "sqlalchemy"}


def test_parse_pyproject_toml_poetry_excludes_python_itself(manifest_parsers):
    text = """
[tool.poetry.dependencies]
python = "^3.12"
django = "^5.0"
"""
    deps = manifest_parsers.parse_pyproject_toml(text)
    names = {d["name"] for d in deps}
    assert names == {"django"}


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------


def test_parse_go_mod(manifest_parsers):
    text = """
module example.com/app

go 1.22

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/stretchr/testify v1.8.4
)

require golang.org/x/text v0.14.0
"""
    deps = manifest_parsers.parse_go_mod(text)
    by_name = {d["name"]: d for d in deps}
    assert by_name["github.com/gin-gonic/gin"]["version"] == "v1.9.1"
    assert by_name["github.com/stretchr/testify"]["version"] == "v1.8.4"
    assert by_name["golang.org/x/text"]["version"] == "v0.14.0"


# ---------------------------------------------------------------------------
# Ruby / PHP / .NET / Rust
# ---------------------------------------------------------------------------


def test_parse_gemfile(manifest_parsers):
    text = """
source "https://rubygems.org"
gem "rails", "~> 7.1"
gem "sinatra"
"""
    deps = manifest_parsers.parse_gemfile(text)
    by_name = {d["name"]: d for d in deps}
    assert by_name["rails"]["version"] == "~> 7.1"
    assert by_name["sinatra"]["version"] is None


def test_parse_composer_json(manifest_parsers):
    text = """
    {
      "require": {"php": ">=8.1", "laravel/framework": "^10.0"},
      "require-dev": {"phpunit/phpunit": "^10.0"}
    }
    """
    deps = manifest_parsers.parse_composer_json(text)
    names = {d["name"] for d in deps}
    assert names == {"laravel/framework", "phpunit/phpunit"}


def test_parse_csproj(manifest_parsers):
    text = (
        '<Project Sdk="Microsoft.NET.Sdk.Web">'
        '<ItemGroup><PackageReference Include="Microsoft.AspNetCore.App" Version="8.0.0" /></ItemGroup>'
        "</Project>"
    )
    deps = manifest_parsers.parse_csproj(text)
    assert deps == [
        {"ecosystem": "nuget", "name": "Microsoft.AspNetCore.App", "version": "8.0.0", "scope": "runtime"}
    ]


def test_parse_cargo_toml(manifest_parsers):
    text = """
[dependencies]
actix-web = "4.4"
serde = { version = "1.0", features = ["derive"] }
"""
    deps = manifest_parsers.parse_cargo_toml(text)
    by_name = {d["name"]: d for d in deps}
    assert by_name["actix-web"]["version"] == "4.4"
    assert by_name["serde"]["version"] == "1.0"


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


def test_parse_manifest_dispatches_by_filename(manifest_parsers):
    deps = manifest_parsers.parse_manifest("package.json", ".json", '{"dependencies": {"express": "^4"}}')
    assert deps[0]["name"] == "express"


def test_parse_manifest_dispatches_by_extension(manifest_parsers):
    text = '<Project><ItemGroup><PackageReference Include="Foo" Version="1.0"/></ItemGroup></Project>'
    deps = manifest_parsers.parse_manifest("Foo.csproj", ".csproj", text)
    assert deps[0]["name"] == "Foo"


def test_parse_manifest_unknown_returns_empty(manifest_parsers):
    assert manifest_parsers.parse_manifest("README.md", ".md", "hello") == []
