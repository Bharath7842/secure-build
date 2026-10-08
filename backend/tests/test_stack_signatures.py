"""Coverage for the dependency-coordinate -> framework signature table
(backend/sast_engine/pipeline/stack_signatures.py).
"""

from pathlib import Path

import pytest

pytest.importorskip("langgraph")

from app.config import settings  # noqa: E402
from app.services.agent_bridge import _load_agent_module  # noqa: E402


@pytest.fixture()
def stack_signatures(monkeypatch):
    import sys

    engine_dir = Path(__file__).resolve().parents[1] / "sast_engine"
    monkeypatch.setattr(settings, "sast_framework_path", str(engine_dir))
    sys.modules.pop("sast_scan_agent", None)
    _load_agent_module()
    return sys.modules["pipeline.stack_signatures"]


def test_match_dependency_exact(stack_signatures):
    sig = stack_signatures.match_dependency("npm", "express")
    assert sig["label"] == "Express.js"
    assert sig["category"] == "rest-framework"


def test_match_dependency_wildcard_groupid(stack_signatures):
    sig = stack_signatures.match_dependency("maven", "org.jboss.resteasy:resteasy-jaxrs")
    assert sig["label"] == "JBoss RESTEasy (JAX-RS)"


def test_match_dependency_case_insensitive(stack_signatures):
    assert stack_signatures.match_dependency("npm", "EXPRESS") is not None


def test_match_dependency_unknown_returns_none(stack_signatures):
    assert stack_signatures.match_dependency("maven", "com.example:totally-unknown-lib") is None


def test_match_dependency_is_ecosystem_scoped(stack_signatures):
    """A name that matches in one ecosystem must not match in another —
    otherwise an npm package coincidentally named like a Maven artifact
    could produce a nonsensical cross-ecosystem match."""
    assert stack_signatures.match_dependency("pypi", "express") is None


def test_match_servlet_api_as_java_servlet_jsp(stack_signatures):
    javax = stack_signatures.match_dependency("maven", "javax.servlet:javax.servlet-api")
    assert javax["label"] == "Java Servlet/JSP"
    jakarta = stack_signatures.match_dependency("maven", "jakarta.servlet:jakarta.servlet-api")
    assert jakarta["label"] == "Java Servlet/JSP"


def test_match_all_splits_recognized_and_unrecognized(stack_signatures):
    deps = [
        {"ecosystem": "maven", "name": "org.apache.axis2:axis2-kernel", "version": "1.7.9", "scope": "runtime"},
        {"ecosystem": "maven", "name": "com.example:mystery-lib", "version": "1.0", "scope": "runtime"},
    ]
    recognized, unrecognized = stack_signatures.match_all(deps)
    assert len(recognized) == 1
    assert recognized[0]["label"] == "Apache Axis2 SOAP"
    assert recognized[0]["category"] == "xml-soap"
    assert len(unrecognized) == 1
    assert unrecognized[0]["name"] == "com.example:mystery-lib"
    # unrecognized entries pass through unchanged — nothing silently dropped,
    # nothing fabricated either.
    assert "label" not in unrecognized[0]
