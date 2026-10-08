"""Deterministic (--no-llm) coverage of the discovery agent's nodes.

Loaded the same way `agent_bridge._load_agent_module()` loads it in
production, so this also guards against import/wiring regressions.
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
def project_tree(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==3.0\n", encoding="utf-8")
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "auth.py").write_text("def login():\n    pass\n", encoding="utf-8")
    (app_dir / "models.py").write_text("class User:\n    pass\n", encoding="utf-8")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_app.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    return tmp_path


def _initial_state(agent, project_tree, **overrides):
    state = {
        "local_path": str(project_tree),
        "scope": None,
        "context_note": "",
        "verbose": False,
        "verbose_files": False,
        "use_llm": False,
        "persist_to_disk": False,
        "_tracer": agent.AgentTrace(verbose=False),
    }
    state.update(overrides)
    return state


def test_format_project_structure_tree_modules_and_packages(agent, tmp_path):
    """Tree stays at module level — packages summarized, no .java/.ts listing."""
    (tmp_path / "pom.xml").write_text("<project/>\n", encoding="utf-8")
    api = tmp_path / "backend" / "ssir-api"
    (api / "src" / "main" / "java" / "tns" / "com" / "ssir" / "controller").mkdir(parents=True)
    (api / "src" / "main" / "java" / "tns" / "com" / "ssir" / "dto").mkdir(parents=True)
    (api / "pom.xml").write_text("<project/>\n", encoding="utf-8")
    (api / "src" / "main" / "java" / "tns" / "com" / "ssir" / "controller" / "AuthController.java").write_text(
        "class AuthController {}\n", encoding="utf-8"
    )
    (api / "src" / "main" / "java" / "tns" / "com" / "ssir" / "dto" / "UserDto.java").write_text(
        "class UserDto {}\n", encoding="utf-8"
    )
    fe = tmp_path / "frontend" / "modules" / "common"
    fe.mkdir(parents=True)
    (fe / "index.ts").write_text("export {};\n", encoding="utf-8")
    (fe / "package.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "frontend" / "package.json").write_text("{}\n", encoding="utf-8")
    login = tmp_path / "frontend" / "modules" / "role-based-login" / "src" / "app"
    login.mkdir(parents=True)
    (login / "app.ts").write_text("export {};\n", encoding="utf-8")

    state = _initial_state(agent, tmp_path)
    result = agent.node_scan_directory(state)
    files = result["scan"]["files"]
    tree = agent._format_project_structure_tree(files, project_name="Curd Pro")
    text = "\n".join(tree)

    assert text.startswith("Curd Pro:")
    assert "pom.xml (parent)" in text
    assert "pom.xml (child)" in text
    assert "package.json" in text
    assert "ssir-api/" in text
    assert "common/" in text
    assert "role-based-login/" in text
    # Packages collapsed into one summary — not expanded as folders.
    assert "controller/" not in text
    assert "dto/" not in text
    assert "AuthController.java" not in text
    assert "src/…" in text
    assert "├──" in text or "└──" in text
    # Keep it short — module-level, not a deep package dump.
    assert len(tree) < 30


def test_node_scan_directory_skips_dotdirs_and_css(agent, tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==3.0\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "styles.css").write_text("body { color: red; }\n", encoding="utf-8")
    (tmp_path / "app.scss").write_text("$x: 1;\n", encoding="utf-8")
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text("[core]\n", encoding="utf-8")
    settings_dir = tmp_path / ".settings"
    settings_dir.mkdir()
    (settings_dir / "org.eclipse.jdt.core.prefs").write_text("x=1\n", encoding="utf-8")

    state = _initial_state(agent, tmp_path)
    result = agent.node_scan_directory(state)
    scan = result["scan"]
    paths = {f["path"] for f in scan["files"]}
    assert paths == {"requirements.txt", "app.py"}
    assert scan["total_files"] == 2


def test_node_scan_directory_skips_images_dotfiles_wrappers_and_specs(agent, tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\r\n")
    (tmp_path / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
    (tmp_path / "mvnw.cmd").write_text("@echo off\n", encoding="utf-8")
    (tmp_path / "mvnw").write_text("#!/bin/sh\n", encoding="utf-8")
    (tmp_path / "UT.properties").write_text("url=http://localhost\n", encoding="utf-8")
    gradle_wrapper_dir = tmp_path / "gradle" / "wrapper"
    gradle_wrapper_dir.mkdir(parents=True)
    (gradle_wrapper_dir / "gradle-wrapper.properties").write_text(
        "distributionUrl=https://services.gradle.org/distributions/gradle-8.0-bin.zip\n", encoding="utf-8"
    )
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "auth.spec.ts").write_text("describe('auth', () => {});\n", encoding="utf-8")
    (src_dir / "auth.test.tsx").write_text("test('x', () => {});\n", encoding="utf-8")
    (src_dir / "auth.ts").write_text("export const x = 1;\n", encoding="utf-8")

    state = _initial_state(agent, tmp_path)
    result = agent.node_scan_directory(state)
    paths = {f["path"] for f in result["scan"]["files"]}
    assert paths == {"app.py", "src/auth.ts"}


def test_node_scan_directory_excludes_non_application_properties(agent, tmp_path):
    """Prove .properties files except Spring Boot application[-profile].properties
    are excluded from the walk. A Struts i18n bundle that merely starts with
    the word 'application' must not slip through."""
    (tmp_path / "pom.xml").write_text("<project/>\n", encoding="utf-8")
    (tmp_path / "random.properties").write_text("key=value\n", encoding="utf-8")
    (tmp_path / "ApplicationResources_lt.properties").write_text(
        "password=Slaptažodis\n", encoding="utf-8"
    )
    res_dir = tmp_path / "src" / "main" / "resources"
    res_dir.mkdir(parents=True)
    (res_dir / "application.properties").write_text("db.url=jdbc:mysql://localhost\n", encoding="utf-8")
    (res_dir / "application-prod.properties").write_text("db.password=secret\n", encoding="utf-8")

    state = _initial_state(agent, tmp_path)
    state.update(agent.node_scan_directory(state))
    scan_paths = {f["path"] for f in state["scan"]["files"]}
    assert "random.properties" not in scan_paths
    assert "ApplicationResources_lt.properties" not in scan_paths
    assert "src/main/resources/application.properties" in scan_paths
    assert "src/main/resources/application-prod.properties" in scan_paths

    # Verify risk mapping still flags application-prod.properties as CRITICAL
    state.update(agent.node_analyze_tech_stack(state))
    state.update(agent.node_categorize_files(state))
    state.update(agent.node_map_modules_and_risk(state))
    by_path = {f["path"]: f["risk_level"] for f in state["module_plan"]["files"]}
    assert by_path["src/main/resources/application-prod.properties"] == "CRITICAL"


def test_is_excluded_properties_file_anchors_spring_naming(agent):
    excluded = agent._is_excluded_properties_file
    assert excluded("ApplicationResources_lt.properties", ".properties") is True
    assert excluded("ApplicationResources.properties", ".properties") is True
    assert excluded("messages_lt.properties", ".properties") is True
    assert excluded("random.properties", ".properties") is True
    assert excluded("application.properties", ".properties") is False
    assert excluded("application-prod.properties", ".properties") is False
    assert excluded("application-dev.properties", ".properties") is False
    assert excluded("Application.properties", ".properties") is False
    assert excluded("app.py", ".py") is False


def test_node_scan_directory_finds_all_files(agent, project_tree):
    state = _initial_state(agent, project_tree)
    result = agent.node_scan_directory(state)
    scan = result["scan"]
    assert scan["total_files"] == 4
    assert "requirements.txt" in scan["marker_files_found"]
    paths = {f["path"] for f in scan["files"]}
    assert paths == {"requirements.txt", "app/auth.py", "app/models.py", "tests/test_app.py"}


def test_node_analyze_tech_stack_heuristic_only_when_use_llm_false(agent, project_tree):
    """No LLM call happens (use_llm=False just controls the — currently
    nonexistent — future LLM step; tech-stack detection itself is always
    deterministic). requirements.txt declares flask==3.0, which the
    dependency-signature scan recognizes without needing any AST coverage
    for Python — proving tech_stack now reflects the real framework instead
    of the bare "python" stack key."""
    state = _initial_state(agent, project_tree)
    state.update(agent.node_scan_directory(state))
    result = agent.node_analyze_tech_stack(state)
    llm_analysis = result["llm_analysis"]
    assert llm_analysis["heuristic_stacks"] == ["python"]
    assert llm_analysis["llm_used"] is False
    assert llm_analysis["tech_stack"] == "Flask"
    assert llm_analysis["project_type"] == "REST API"
    dependency_summary = llm_analysis["dependency_summary"]
    assert dependency_summary["manifests_parsed"] == ["requirements.txt"]
    assert {f["label"] for f in dependency_summary["frameworks"]} == {"Flask"}


def test_node_analyze_tech_stack_fixes_non_spring_java_false_negative(agent, tmp_path):
    """Regression test for the reported bug: a legacy Java EE project using
    JAX-RS/RESTEasy + EJB + Axis2 SOAP has zero Spring annotations
    (ast_struct.py's vocabulary is Spring-only), so before the dependency
    scan existed this reported tech_stack="Unrecognized stack",
    project_type="unknown" — exactly the "0 REST endpoint(s) found... none
    flagged" failure from the bug report. The dependency-manifest scan
    fixes this without any LLM call, purely from parsing pom.xml."""
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

    state = _initial_state(agent, tmp_path)
    state.update(agent.node_scan_directory(state))
    result = agent.node_analyze_tech_stack(state)
    llm_analysis = result["llm_analysis"]

    assert llm_analysis["llm_used"] is False
    assert llm_analysis["tech_stack"] != "Unrecognized stack"
    assert "JBoss RESTEasy (JAX-RS)" in llm_analysis["tech_stack"]
    assert "EJB" in llm_analysis["tech_stack"]
    assert llm_analysis["project_type"] == "REST API"
    assert llm_analysis["confidence"] in ("medium", "high")


def test_node_categorize_files_buckets_by_stack_rules(agent, project_tree):
    state = _initial_state(agent, project_tree)
    state.update(agent.node_scan_directory(state))
    state.update(agent.node_analyze_tech_stack(state))
    result = agent.node_categorize_files(state)
    categorized = result["categorized"]
    assert categorized["dependency"] == ["requirements.txt"]
    assert set(categorized["source"]) == {"app/auth.py", "app/models.py"}
    assert categorized["test"] == ["tests/test_app.py"]


def test_node_map_modules_and_risk_flags_critical_and_low(agent, project_tree):
    state = _initial_state(agent, project_tree)
    state.update(agent.node_scan_directory(state))
    state.update(agent.node_analyze_tech_stack(state))
    state.update(agent.node_categorize_files(state))
    result = agent.node_map_modules_and_risk(state)
    module_plan = result["module_plan"]
    assert module_plan["risk_counts"] == {"CRITICAL": 2, "HIGH": 0, "MEDIUM": 1, "LOW": 1}
    by_path = {f["path"]: f["risk_level"] for f in module_plan["files"]}
    assert by_path["requirements.txt"] == "MEDIUM"
    assert by_path["app/auth.py"] == "CRITICAL"
    assert by_path["app/models.py"] == "CRITICAL"
    assert by_path["tests/test_app.py"] == "LOW"
    assert len(module_plan["scan_priority"]) == 2
    assert {f["path"]: f.get("lang") for f in module_plan["files"]}["app/auth.py"] == "python"
    # Only 2 CRITICAL files against the default 100-file cap, so backfill
    # (default on) fills the rest of the budget with the MEDIUM file, then the
    # LOW file — nothing is left for regex-gated triage in this tiny fixture.
    # risk_level (asserted above) stays MEDIUM/LOW regardless of which tier
    # actually scans the file.
    assert set(module_plan["deep_scan_paths"]) == {
        "app/auth.py", "app/models.py", "requirements.txt", "tests/test_app.py",
    }
    assert module_plan["triage_scan_paths"] == []


def test_node_map_modules_and_risk_no_backfill_when_disabled(agent, project_tree):
    """state["backfill_deep_scan"] = False reproduces the pre-backfill behavior
    exactly — MEDIUM/LOW never enter deep_scan_paths, regardless of headroom."""
    state = _initial_state(agent, project_tree, backfill_deep_scan=False)
    state.update(agent.node_scan_directory(state))
    state.update(agent.node_analyze_tech_stack(state))
    state.update(agent.node_categorize_files(state))
    result = agent.node_map_modules_and_risk(state)
    module_plan = result["module_plan"]
    assert set(module_plan["deep_scan_paths"]) == {"app/auth.py", "app/models.py"}
    assert set(module_plan["triage_scan_paths"]) == {"requirements.txt", "tests/test_app.py"}


def test_node_map_modules_and_risk_backfill_prefers_medium_over_low_and_stays_capped(agent, tmp_path):
    """With limited headroom, backfill picks MEDIUM files before LOW ones and
    never pushes deep_scan_paths past the cap."""
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "auth.py").write_text("def login():\n    pass\n", encoding="utf-8")
    (app_dir / "models.py").write_text("class User:\n    pass\n", encoding="utf-8")
    # requirements.txt (root) is the sole MEDIUM-risk candidate; several LOW-risk
    # test files give the LOW tier more than one option too, so a naive
    # "just take whatever's first" implementation couldn't accidentally pass.
    (tmp_path / "requirements.txt").write_text("flask==3.0\n", encoding="utf-8")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    for i in range(3):
        (tests_dir / f"test_{i}.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")

    state = _initial_state(agent, tmp_path, deep_scan_file_cap=3)
    state.update(agent.node_scan_directory(state))
    state.update(agent.node_analyze_tech_stack(state))
    state.update(agent.node_categorize_files(state))
    result = agent.node_map_modules_and_risk(state)
    module_plan = result["module_plan"]
    by_path = {f["path"]: f["risk_level"] for f in module_plan["files"]}

    assert len(module_plan["deep_scan_paths"]) == 3  # 2 CRITICAL + exactly 1 backfilled, never past cap
    backfilled = set(module_plan["deep_scan_paths"]) - {"app/auth.py", "app/models.py"}
    assert len(backfilled) == 1
    (backfilled_path,) = backfilled
    assert by_path[backfilled_path] == "MEDIUM"  # MEDIUM chosen over any LOW candidate


def test_maven_java_profile_flags_exception_handlers_high_regardless_of_package(agent):
    """Regression guard for a gap found by comparing our tool's output against
    GitLab's taint-flow SAST on the same repo: a *ExceptionHandler.java class
    living outside the controller/ package (e.g. in config/) used to fall
    through to the generic src/main/java/ -> MEDIUM rule, keeping it out of the
    LLM deep-scan tier entirely — even though it builds HTTP responses from
    exception data just like a controller does."""
    rules = agent.STACK_PROFILES["maven-java"]["rules"]

    matched = agent._match_rules(
        "src/main/java/tns/com/ssir/config/GlobalExceptionHandler.java", rules
    )
    assert matched is not None
    risk, _reason, _category = matched
    assert risk == "HIGH"

    matched_advice = agent._match_rules(
        "src/main/java/tns/com/ssir/config/RestControllerAdvice.java", rules
    )
    assert matched_advice[0] == "HIGH"

    # A same-package file that is NOT an exception handler must still fall
    # through to the generic fallback — the new rule must not over-match.
    matched_other = agent._match_rules(
        "src/main/java/tns/com/ssir/config/AppConfig.java", rules
    )
    assert matched_other[0] == "MEDIUM"


def test_maven_java_profile_flags_security_config_critical_regardless_of_package(agent):
    """Regression guard for a second gap comparison: a *SecurityConfig.java class
    (the standard Spring Boot naming convention for the CSRF/CORS/authorization
    bean, wherever it lives — config/, security/, or the app's root package) used
    to fall through to the generic src/main/java/ -> MEDIUM rule unless it
    happened to sit in a security/auth directory. Regex catalog rules like
    csrf-disabled still run against MEDIUM files in the triage tier, but this
    keeps the file out of full LLM deep-scan review entirely."""
    rules = agent.STACK_PROFILES["maven-java"]["rules"]

    for path in (
        "src/main/java/com/example/config/SecurityConfig.java",
        "src/main/java/com/example/config/WebSecurityConfig.java",
        "src/main/java/com/example/security/SecurityFilterChainConfig.java",
    ):
        matched = agent._match_rules(path, rules)
        assert matched is not None, path
        assert matched[0] == "CRITICAL", path

    # A same-package file that isn't a security config must still fall through.
    matched_other = agent._match_rules(
        "src/main/java/com/example/config/AppConfig.java", rules
    )
    assert matched_other[0] == "MEDIUM"


def test_files_for_risk_levels_splits_deep_and_triage_tiers_skips_binaries(agent):
    llm = agent.llm_file_scan
    module_plan = {
        "files": [
            {"path": "a.py", "risk_level": "CRITICAL"},
            {"path": "b.py", "risk_level": "HIGH"},
            {"path": "c.py", "risk_level": "MEDIUM"},
            {"path": "d.py", "risk_level": "LOW"},
            {"path": "e.class", "risk_level": "CRITICAL"},
        ]
    }
    deep = llm.files_for_risk_levels(module_plan, llm.LLM_RISK_LEVELS)
    assert [e["path"] for e in deep] == ["a.py", "b.py"]
    triage = llm.files_for_risk_levels(module_plan, llm.TRIAGE_RISK_LEVELS)
    assert [e["path"] for e in triage] == ["c.py", "d.py"]
    # The two tiers partition the scannable files — nothing is scanned twice
    # and nothing (bar the binary) falls through the gap.
    assert {e["path"] for e in deep} & {e["path"] for e in triage} == set()


def test_schema_cvs_log4j_are_dropped_from_discovery(agent, tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==3.0\n", encoding="utf-8")
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "auth.py").write_text("def login():\n    pass\n", encoding="utf-8")
    (tmp_path / "app" / "config.py").write_text("DEBUG = True\n", encoding="utf-8")
    (tmp_path / "schema.xsd").write_text("<schema/>\n", encoding="utf-8")
    (tmp_path / "svc.wsdl").write_text("<definitions/>\n", encoding="utf-8")
    (tmp_path / "xsd").mkdir()
    (tmp_path / "xsd" / "foo.xml").write_text("<foo/>\n", encoding="utf-8")
    (tmp_path / "configuration").mkdir()
    (tmp_path / "configuration" / "app.xml").write_text("<app/>\n", encoding="utf-8")
    (tmp_path / "NPG" / "config").mkdir(parents=True)
    (tmp_path / "NPG" / "config" / "MsgHandler_11_log4j.xml").write_text("<log4j/>\n", encoding="utf-8")
    (tmp_path / "NPG" / "config" / "ApplicationResources.properties").write_text("ok=1\n", encoding="utf-8")
    (tmp_path / "NPG" / "config" / "NPG.xml").write_text("<npg/>\n", encoding="utf-8")
    (tmp_path / "NPG" / "config" / "Start_EMASim").write_text("#!/bin/sh\n", encoding="utf-8")
    (tmp_path / "CVS").mkdir()
    (tmp_path / "CVS" / "Repository").write_text("module\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "CVS").mkdir()
    (tmp_path / "src" / "CVS" / "Tag").write_text("T1.0\n", encoding="utf-8")
    (tmp_path / "log4j.xml").write_text("<log4j/>\n", encoding="utf-8")
    (tmp_path / "a.compose").write_text("compose\n", encoding="utf-8")
    (tmp_path / "a.csv").write_text("a,b\n", encoding="utf-8")
    (tmp_path / "META-INF").mkdir()
    (tmp_path / "META-INF" / "MANIFEST.MF").write_text("Manifest-Version: 1.0\n", encoding="utf-8")
    (tmp_path / ".project").write_text("<projectDescription/>\n", encoding="utf-8")

    state = _initial_state(agent, tmp_path)
    state.update(agent.node_scan_directory(state))
    state.update(agent.node_analyze_tech_stack(state))
    state.update(agent.node_categorize_files(state))
    result = agent.node_map_modules_and_risk(state)
    module_plan = result["module_plan"]

    discovered = {f["path"] for f in module_plan["files"]}
    assert "app/auth.py" in discovered
    assert "app/config.py" in discovered
    skipped = {
        "schema.xsd", "svc.wsdl", "xsd/foo.xml", "configuration/app.xml",
        "NPG/config/MsgHandler_11_log4j.xml",
        "NPG/config/ApplicationResources.properties",
        "NPG/config/NPG.xml", "NPG/config/Start_EMASim",
        "CVS/Repository", "src/CVS/Tag", "log4j.xml",
        "a.compose", "a.csv", "META-INF/MANIFEST.MF", ".project",
    }
    assert discovered.isdisjoint(skipped)

    queued = set(module_plan["deep_scan_paths"]) | set(module_plan["triage_scan_paths"])
    assert "app/auth.py" in queued
    assert "app/config.py" in queued
    assert queued.isdisjoint(skipped)


def test_node_map_modules_and_risk_caps_deep_scan_and_overflows_to_triage(agent, tmp_path):
    """A repo with more CRITICAL files than DEEP_SCAN_FILE_CAP (100) only sends
    the first 100 (bucket order) to the full LLM scan; the rest join the
    regex-gated triage tier instead of being dropped."""
    (tmp_path / "requirements.txt").write_text("flask==3.0\n", encoding="utf-8")
    for i in range(120):
        (tmp_path / f"auth_{i}").mkdir(exist_ok=True)
        (tmp_path / f"auth_{i}" / "auth.py").write_text("def login():\n    pass\n", encoding="utf-8")

    state = _initial_state(agent, tmp_path)
    state.update(agent.node_scan_directory(state))
    state.update(agent.node_analyze_tech_stack(state))
    state.update(agent.node_categorize_files(state))
    result = agent.node_map_modules_and_risk(state)
    module_plan = result["module_plan"]

    assert module_plan["risk_counts"]["CRITICAL"] == 120  # true risk count is untouched by the cap
    assert len(module_plan["deep_scan_paths"]) == agent.llm_file_scan.DEEP_SCAN_FILE_CAP == 100
    assert set(module_plan["deep_scan_paths"]) <= {f"auth_{i}/auth.py" for i in range(120)}

    # The 20 overflow CRITICAL files join triage ahead of requirements.txt (MEDIUM).
    triage = module_plan["triage_scan_paths"]
    assert len(triage) == 21
    assert triage[-1] == "requirements.txt"
    overflow = set(triage[:-1])
    assert len(overflow) == 20
    assert overflow <= {f"auth_{i}/auth.py" for i in range(120)}
    # No file is scheduled for both tiers.
    assert overflow.isdisjoint(module_plan["deep_scan_paths"])


def test_node_map_modules_and_risk_no_overflow_when_under_cap(agent, project_tree):
    """A repo with fewer CRITICAL/HIGH files than the cap sees zero overflow —
    every CRITICAL/HIGH file still lands in the deep tier."""
    state = _initial_state(agent, project_tree)
    state.update(agent.node_scan_directory(state))
    state.update(agent.node_analyze_tech_stack(state))
    state.update(agent.node_categorize_files(state))
    result = agent.node_map_modules_and_risk(state)
    module_plan = result["module_plan"]

    assert "app/auth.py" in module_plan["deep_scan_paths"]
    assert "app/auth.py" not in module_plan["triage_scan_paths"]


def test_node_map_modules_and_risk_honors_deep_scan_file_cap_override(agent, tmp_path):
    """state["deep_scan_file_cap"] overrides the default without needing a
    100+ file fixture."""
    (tmp_path / "requirements.txt").write_text("flask==3.0\n", encoding="utf-8")
    for i in range(5):
        (tmp_path / f"auth_{i}").mkdir(exist_ok=True)
        (tmp_path / f"auth_{i}" / "auth.py").write_text("def login():\n    pass\n", encoding="utf-8")

    state = _initial_state(agent, tmp_path, deep_scan_file_cap=2)
    state.update(agent.node_scan_directory(state))
    state.update(agent.node_analyze_tech_stack(state))
    state.update(agent.node_categorize_files(state))
    result = agent.node_map_modules_and_risk(state)
    module_plan = result["module_plan"]

    assert len(module_plan["deep_scan_paths"]) == 2
    assert len(module_plan["triage_scan_paths"]) == 4  # 3 overflow auth.py + requirements.txt
    assert "critical_scan_paths" not in module_plan


def test_persist_to_disk_writes_json_and_sqlite(agent, project_tree, tmp_path):
    out_dir = tmp_path / "out"
    db_path = tmp_path / "history.db"
    state = _initial_state(
        agent,
        project_tree,
        persist_to_disk=True,
        scan_id="test-scan-id",
        output_dir=str(out_dir),
        db_path=str(db_path),
    )
    state.update(agent.node_scan_directory(state))
    state.update(agent.node_analyze_tech_stack(state))
    state.update(agent.node_categorize_files(state))
    state.update(agent.node_map_modules_and_risk(state))
    result = agent.persist_to_disk(state)
    assert Path(result["json_path"]).is_file()
    assert Path(result["db_path"]).is_file()


def test_build_graph_has_scan_critical_files_and_generate_report_nodes(agent):
    graph = agent.build_graph()
    nodes = set(graph.get_graph().nodes)
    assert "map_modules_and_risk" in nodes
    assert "scan_deep_files" in nodes
    assert "scan_triage_files" in nodes
    assert "generate_report" in nodes
    assert "build_call_graph" in nodes
    assert "discover_flows" in nodes
    assert "verify_flow_slices" in nodes
    assert "derive_runtime_rules" in nodes


def test_build_graph_end_to_end_no_llm(agent, project_tree):
    graph = agent.build_graph()
    tracer = agent.AgentTrace(verbose=False)
    initial_state = _initial_state(
        agent,
        project_tree,
        usage=agent.init_usage(None, None),
        _tracer=tracer,
    )
    final_state = agent.invoke_graph(graph, initial_state)
    assert final_state["scan"]["total_files"] == 4
    assert final_state["llm_analysis"]["llm_used"] is False
    assert final_state["module_plan"]["risk_counts"]["CRITICAL"] == 2
    # use_llm=False -> scan_deep_files skips the LLM pass; the regex-only
    # triage tier still runs (it needs no LLM) but this fixture has no hits,
    # so generate_report produces an empty (zeroed) report.
    assert final_state["report"] == {
        "files_scanned": 0, "tp_count": 0, "fp_count": 0, "unverified_count": 0,
        "by_owasp_category": {}, "chunk_errors": 0,
    }
    node_order = [e["node"] for e in tracer.events]
    assert (
        node_order.index("map_modules_and_risk")
        < node_order.index("build_call_graph")
        < node_order.index("derive_runtime_rules")
        < node_order.index("discover_flows")
        < node_order.index("verify_flow_slices")
        < node_order.index("scan_deep_files")
        < node_order.index("scan_triage_files")
        < node_order.index("generate_report")
    )


def test_node_scan_deep_files_skips_when_use_llm_false(agent, project_tree):
    state = _initial_state(agent, project_tree)  # use_llm=False by default
    state.update(agent.node_scan_directory(state))
    state.update(agent.node_analyze_tech_stack(state))
    state.update(agent.node_categorize_files(state))
    state.update(agent.node_map_modules_and_risk(state))
    result = agent.node_scan_deep_files(state)
    assert result["scan_results"] == {"files_scanned": 0, "tp_count": 0, "fp_count": 0, "files": []}


def test_node_scan_deep_files_scans_every_llm_tier_file_no_regex_gate(agent, project_tree, monkeypatch):
    """No zero-regex-hit skip gate: node_scan_deep_files must hand every
    CRITICAL/HIGH/MEDIUM file to the LLM scan. LOW files stay out of this node."""
    state = _initial_state(agent, project_tree, use_llm=True, usage=agent.init_usage(None, None))
    state.update(agent.node_scan_directory(state))
    state.update(agent.node_analyze_tech_stack(state))
    state.update(agent.node_categorize_files(state))
    state.update(agent.node_map_modules_and_risk(state))

    calls = []

    def fake_scan_critical_files(*, module_plan, **kwargs):
        calls.append(module_plan)
        llm_files = [
            f for f in module_plan["files"]
            if f["risk_level"] in ("CRITICAL", "HIGH", "MEDIUM")
        ]
        return {"files_scanned": len(llm_files), "tp_count": 0, "fp_count": 0, "files": []}

    monkeypatch.setattr(agent.llm_file_scan, "scan_deep_files", fake_scan_critical_files)

    result = agent.node_scan_deep_files(state)
    assert len(calls) == 1
    llm_paths = {
        f["path"] for f in calls[0]["files"]
        if f["risk_level"] in ("CRITICAL", "HIGH", "MEDIUM")
    }
    assert llm_paths == {"app/auth.py", "app/models.py", "requirements.txt"}
    assert result["scan_results"]["files_scanned"] == 3


def test_node_scan_deep_files_threads_findings_writer_from_state(agent, project_tree, monkeypatch):
    state = _initial_state(agent, project_tree, use_llm=True, usage=agent.init_usage(None, None))
    state.update(agent.node_scan_directory(state))
    state.update(agent.node_analyze_tech_stack(state))
    state.update(agent.node_categorize_files(state))
    state.update(agent.node_map_modules_and_risk(state))

    captured = []

    def fake_scan_critical_files(*, findings_writer, **kwargs):
        captured.append(findings_writer)
        return {"files_scanned": 0, "tp_count": 0, "fp_count": 0, "files": []}

    monkeypatch.setattr(agent.llm_file_scan, "scan_deep_files", fake_scan_critical_files)

    marker = object()
    state["findings_writer"] = marker
    agent.node_scan_deep_files(state)
    assert captured == [marker]


def test_node_scan_deep_files_threads_suppress_low_confidence_fp_from_state(agent, project_tree, monkeypatch):
    state = _initial_state(agent, project_tree, use_llm=True, usage=agent.init_usage(None, None))
    state.update(agent.node_scan_directory(state))
    state.update(agent.node_analyze_tech_stack(state))
    state.update(agent.node_categorize_files(state))
    state.update(agent.node_map_modules_and_risk(state))

    captured = []

    def fake_scan_critical_files(*, suppress_low_confidence_false_positives, **kwargs):
        captured.append(suppress_low_confidence_false_positives)
        return {"files_scanned": 0, "tp_count": 0, "fp_count": 0, "files": []}

    monkeypatch.setattr(agent.llm_file_scan, "scan_deep_files", fake_scan_critical_files)

    # Absent from state -> defaults False.
    agent.node_scan_deep_files(state)
    assert captured == [False]

    state["suppress_low_confidence_false_positives"] = True
    agent.node_scan_deep_files(state)
    assert captured == [False, True]


def test_node_scan_triage_files_skips_when_use_llm_false(agent, project_tree):
    state = _initial_state(agent, project_tree)
    state.update(agent.node_scan_directory(state))
    state.update(agent.node_analyze_tech_stack(state))
    state.update(agent.node_categorize_files(state))
    state.update(agent.node_map_modules_and_risk(state))
    result = agent.node_scan_triage_files(state)
    assert result["triage_scan_results"]["files_scanned"] == 0
    assert result["triage_scan_results"]["files"] == []


def test_node_scan_triage_files_threads_findings_writer_from_state(agent, project_tree, monkeypatch):
    # backfill_deep_scan=False: this tiny fixture's MEDIUM/LOW files would
    # otherwise backfill entirely into deep_scan_paths (default-on backfill),
    # leaving nothing queued for this node to actually triage.
    state = _initial_state(
        agent, project_tree, use_llm=True, usage=agent.init_usage(None, None),
        backfill_deep_scan=False,
    )
    state.update(agent.node_scan_directory(state))
    state.update(agent.node_analyze_tech_stack(state))
    state.update(agent.node_categorize_files(state))
    state.update(agent.node_map_modules_and_risk(state))

    captured = []

    def fake_scan_low_files(*, findings_writer, **kwargs):
        captured.append(findings_writer)
        return {"files_scanned": 0, "tp_count": 0, "fp_count": 0, "files": []}

    monkeypatch.setattr(agent.llm_file_scan, "scan_triage_files", fake_scan_low_files)

    marker = object()
    state["findings_writer"] = marker
    agent.node_scan_triage_files(state)
    assert captured == [marker]


# --- _batch_triage_entries ---------------------------------------------------

def _entry(path, module="(root)"):
    return {"path": path, "module": module, "risk_level": "MEDIUM", "lang": "python"}


def test_batch_triage_entries_groups_by_module_when_multiple(agent):
    entries = [
        _entry("a/x.py", module="a"), _entry("a/y.py", module="a"),
        _entry("b/x.py", module="b"),
    ]
    batches = agent._batch_triage_entries(entries, batch_size=250)
    assert [label for label, _ in batches] == ["a", "b"]
    assert [e["path"] for e in dict(batches)["a"]] == ["a/x.py", "a/y.py"]
    assert [e["path"] for e in dict(batches)["b"]] == ["b/x.py"]


def test_batch_triage_entries_fixed_size_when_single_module(agent):
    entries = [_entry(f"f{i}.py") for i in range(5)]
    batches = agent._batch_triage_entries(entries, batch_size=2)
    assert [label for label, _ in batches] == ["batch 1", "batch 2", "batch 3"]
    sizes = [len(batch) for _, batch in batches]
    assert sizes == [2, 2, 1]  # correctly-sized final partial batch
    # original order preserved across batch boundaries
    flattened = [e["path"] for _, batch in batches for e in batch]
    assert flattened == [f"f{i}.py" for i in range(5)]


def test_batch_triage_entries_empty_input(agent):
    assert agent._batch_triage_entries([], batch_size=250) == []


def test_node_scan_triage_files_routes_overflow_critical_through_regex_gate(agent, tmp_path, monkeypatch):
    """A CRITICAL file beyond a small deep_scan_file_cap is routed into the
    triage tier by node_map_modules_and_risk; confirm the node actually hands
    it to scan_triage_files (via `entries`), not silently dropping it."""
    (tmp_path / "requirements.txt").write_text("flask==3.0\n", encoding="utf-8")
    (tmp_path / "auth_kept").mkdir()
    (tmp_path / "auth_kept" / "auth.py").write_text("password = 'hunter2'\n", encoding="utf-8")
    (tmp_path / "auth_overflow").mkdir()
    (tmp_path / "auth_overflow" / "auth.py").write_text("password = 'hunter2'\n", encoding="utf-8")

    state = _initial_state(agent, tmp_path, use_llm=True, usage=agent.init_usage(None, None),
                            deep_scan_file_cap=1)
    state.update(agent.node_scan_directory(state))
    state.update(agent.node_analyze_tech_stack(state))
    state.update(agent.node_categorize_files(state))
    state.update(agent.node_map_modules_and_risk(state))
    module_plan = state["module_plan"]
    assert len(module_plan["deep_scan_paths"]) == 1
    overflow_path = [p for p in module_plan["triage_scan_paths"] if p != "requirements.txt"][0]
    assert overflow_path in ("auth_kept/auth.py", "auth_overflow/auth.py")

    seen_paths = []

    def fake_scan_triage_files(*, entries, findings_writer=None, **kwargs):
        paths = [e["path"] for e in entries]
        seen_paths.extend(paths)
        # Simulate a real hit on the overflow CRITICAL entry, as kind=regex —
        # it must not silently disappear, and must not surface as kind=llm.
        findings = (
            [{"kind": "regex", "verdict": "true_positive", "owasp_category": "A07",
              "severity": "HIGH", "line": 1, "rule_id": "secret-password-assign"}]
            if overflow_path in paths else []
        )
        return {
            "files_scanned": 1 if overflow_path in paths else 0,
            "files_regex_scanned": len(paths), "tp_count": 1 if overflow_path in paths else 0,
            "fp_count": 0, "chunk_errors": 0,
            "files": [{"file_path": overflow_path, "findings": findings}] if overflow_path in paths else [],
        }

    monkeypatch.setattr(agent.llm_file_scan, "scan_triage_files", fake_scan_triage_files)
    result = agent.node_scan_triage_files(state)

    # The overflow CRITICAL file really was included among the entries handed
    # to scan_triage_files (across whichever batch it landed in).
    assert overflow_path in seen_paths
    triage_files = {f["file_path"]: f for f in result["triage_scan_results"]["files"]}
    assert overflow_path in triage_files
    assert triage_files[overflow_path]["findings"][0]["kind"] == "regex"


def test_node_scan_triage_files_logs_batch_boundaries_for_multi_module_repo(agent, tmp_path, monkeypatch):
    """A multi-module repo batches by module; the log carries a batch-start
    and batch-complete line per module, and scan_triage_files is called once
    per batch (not once for the whole repo)."""
    (tmp_path / "svc-a" / "pom.xml").parent.mkdir(parents=True)
    (tmp_path / "svc-a" / "pom.xml").write_text("<project/>\n", encoding="utf-8")
    (tmp_path / "svc-a" / "util.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "svc-b" / "pom.xml").parent.mkdir(parents=True)
    (tmp_path / "svc-b" / "pom.xml").write_text("<project/>\n", encoding="utf-8")
    (tmp_path / "svc-b" / "util.py").write_text("x = 1\n", encoding="utf-8")

    # backfill_deep_scan=False: these tiny per-module fixtures have no
    # CRITICAL/HIGH files at all, so default-on backfill would pull every
    # MEDIUM/LOW file into deep_scan_paths instead of queuing them for triage,
    # defeating the point of this batching test.
    state = _initial_state(
        agent, tmp_path, use_llm=True, usage=agent.init_usage(None, None),
        backfill_deep_scan=False,
    )
    state.update(agent.node_scan_directory(state))
    state.update(agent.node_analyze_tech_stack(state))
    state.update(agent.node_categorize_files(state))
    state.update(agent.node_map_modules_and_risk(state))
    module_plan = state["module_plan"]
    assert len(module_plan["triage_scan_paths"]) > 0  # sanity: fixture actually queued triage files

    call_count = []

    def fake_scan_triage_files(*, entries, **kwargs):
        call_count.append(len(entries))
        return {"files_scanned": 0, "files_regex_scanned": len(entries), "tp_count": 0,
                "fp_count": 0, "chunk_errors": 0, "files": []}

    monkeypatch.setattr(agent.llm_file_scan, "scan_triage_files", fake_scan_triage_files)
    agent.node_scan_triage_files(state)

    events = state["_tracer"].events
    batch_starts = [e for e in events if e.get("node") == "scan_triage_files"
                    and e["message"].startswith("Batch ") and "complete" not in e["message"]]
    batch_completes = [e for e in events if e.get("node") == "scan_triage_files"
                       and e["message"].startswith("Batch ") and "complete" in e["message"]]
    assert len(batch_starts) == len(call_count)
    assert len(batch_completes) == len(call_count)
    assert len(call_count) >= 1


def test_node_generate_report_aggregates_by_owasp_category(agent):
    state = {
        "_tracer": agent.AgentTrace(verbose=False),
        "scan_results": {
            "files_scanned": 2, "tp_count": 2, "fp_count": 1,
            "files": [
                {"file_path": "a.py", "findings": [
                    {"owasp_category": "A03:2021-Injection", "verdict": "true_positive"},
                    {"owasp_category": "A03:2021-Injection", "verdict": "false_positive"},
                ]},
                {"file_path": "b.py", "findings": [
                    {"owasp_category": "A07:2021-Identification-and-Authentication-Failures", "verdict": "true_positive"},
                ]},
            ],
        },
        "triage_scan_results": {
            "files_scanned": 1, "tp_count": 0, "fp_count": 1,
            "files": [
                {"file_path": "tests/test_app.py", "findings": [
                    {"owasp_category": "A07:2021-Identification-and-Authentication-Failures", "verdict": "false_positive"},
                ]},
            ],
        },
    }
    result = agent.node_generate_report(state)
    report = result["report"]
    assert report["tp_count"] == 2
    assert report["fp_count"] == 2
    assert report["files_scanned"] == 3
    assert report["by_owasp_category"]["A03:2021-Injection"] == {
        "true_positive": 1, "false_positive": 1, "unverified": 0,
    }
    assert report["by_owasp_category"]["A07:2021-Identification-and-Authentication-Failures"] == {
        "true_positive": 1, "false_positive": 1, "unverified": 0,
    }


# --- node_group_triage_findings ----------------------------------------------

def test_build_graph_has_group_triage_findings_node(agent):
    graph = agent.build_graph()
    nodes = set(graph.get_graph().nodes)
    assert "group_triage_findings" in nodes


def _triage_state(**triage_scan_results_overrides):
    triage_scan_results = {
        "files_scanned": 1, "tp_count": 0, "fp_count": 0, "unverified_count": 1,
        "files": [
            {"file_path": "a.py", "findings": [
                {"rule_id": "secret-password-assign", "line": 1, "severity": "MEDIUM",
                 "matched_text": "password = 'x'", "verdict": "unverified",
                 "verdict_reason": "not reviewed", "kind": "regex", "confidence": None,
                 "file_path": "a.py"},
            ]},
        ],
    }
    triage_scan_results.update(triage_scan_results_overrides)
    return {
        "_tracer": None,  # set per-test
        "local_path": ".",
        "triage_mode": "regex_only",
        "group_triage_mode": True,
        "use_llm": True,
        "llm_provider": None,
        "llm_model": None,
        "usage": None,
        "llm_analysis": {},
        "triage_scan_results": triage_scan_results,
    }


def test_node_group_triage_findings_skips_when_llm_triage_mode(agent, monkeypatch):
    state = _triage_state()
    state["_tracer"] = agent.AgentTrace(verbose=False)
    state["triage_mode"] = "llm_triage"

    def exploding(*_args, **_kwargs):
        raise AssertionError("must not run grouping when triage_mode is llm_triage")

    monkeypatch.setattr(agent.llm_file_scan, "group_unverified_findings", exploding)
    result = agent.node_group_triage_findings(state)
    assert result["triage_scan_results"]["unverified_count"] == 1  # untouched
    assert "triage_group_summary" not in result


def test_node_group_triage_findings_skips_when_disabled(agent, monkeypatch):
    state = _triage_state()
    state["_tracer"] = agent.AgentTrace(verbose=False)
    state["group_triage_mode"] = False

    def exploding(*_args, **_kwargs):
        raise AssertionError("must not run grouping when disabled")

    monkeypatch.setattr(agent.llm_file_scan, "group_unverified_findings", exploding)
    result = agent.node_group_triage_findings(state)
    assert result["triage_scan_results"]["unverified_count"] == 1  # untouched


def test_node_group_triage_findings_skips_when_nothing_unverified(agent, monkeypatch):
    state = _triage_state(unverified_count=0)
    state["_tracer"] = agent.AgentTrace(verbose=False)

    def exploding(*_args, **_kwargs):
        raise AssertionError("must not run grouping when nothing is unverified")

    monkeypatch.setattr(agent.llm_file_scan, "group_unverified_findings", exploding)
    agent.node_group_triage_findings(state)  # must not raise


def test_node_group_triage_findings_makes_no_llm_call_and_leaves_verdicts_unverified(agent):
    """The whole point of this node: grouping alone, no LLM call, no verdict
    changes. Uses the real llm_file_scan.group_unverified_findings (not a
    stub) against a small multi-file fixture sharing one construct."""
    state = _triage_state()
    state["_tracer"] = agent.AgentTrace(verbose=False)
    state["triage_scan_results"]["files"] = [
        {"file_path": "a.py", "findings": [
            {"rule_id": "secret-password-assign", "line": 1, "severity": "MEDIUM",
             "matched_text": "password = 'x'", "verdict": "unverified",
             "verdict_reason": "not reviewed", "kind": "regex", "confidence": None,
             "file_path": "a.py"},
        ]},
        {"file_path": "b.py", "findings": [
            {"rule_id": "secret-password-assign", "line": 1, "severity": "MEDIUM",
             "matched_text": "password = 'x'", "verdict": "unverified",
             "verdict_reason": "not reviewed", "kind": "regex", "confidence": None,
             "file_path": "b.py"},
        ]},
    ]
    state["triage_scan_results"]["unverified_count"] = 2

    result = agent.node_group_triage_findings(state)

    summary = result["triage_group_summary"]
    assert summary["candidate_count"] == 2
    assert summary["group_count"] == 1  # both files share the same construct
    assert summary["groups"][0]["occurrence_count"] == 2

    # verdicts are completely untouched — this node never calls an LLM
    for file_result in result["triage_scan_results"]["files"]:
        for finding in file_result["findings"]:
            assert finding["verdict"] == "unverified"


# --- node_confirm_triage_groups ----------------------------------------------

def test_build_graph_has_confirm_triage_groups_node(agent):
    graph = agent.build_graph()
    nodes = set(graph.get_graph().nodes)
    assert "confirm_triage_groups" in nodes


def _confirm_state(**overrides):
    state = _triage_state()
    state["confirm_triage_groups"] = True
    state["triage_group_summary"] = {
        "candidate_count": 2, "group_count": 1,
        "groups": [{"rule_id": "secret-password-assign", "occurrence_count": 2}],
        "members_by_key": {}, "group_order": [],
    }
    state["verdict_updates_writer"] = None
    state.update(overrides)
    return state


def test_node_confirm_triage_groups_skips_when_disabled(agent, monkeypatch):
    state = _confirm_state(confirm_triage_groups=False)
    state["_tracer"] = agent.AgentTrace(verbose=False)

    def exploding(*_args, **_kwargs):
        raise AssertionError("must not confirm groups when disabled")

    monkeypatch.setattr(agent.llm_file_scan, "group_confirm_unverified_findings", exploding)
    result = agent.node_confirm_triage_groups(state)
    assert "triage_group_summary" not in result  # untouched — passthrough only


def test_node_confirm_triage_groups_skips_when_no_groups(agent, monkeypatch):
    state = _confirm_state(triage_group_summary=None)
    state["_tracer"] = agent.AgentTrace(verbose=False)

    def exploding(*_args, **_kwargs):
        raise AssertionError("must not confirm groups when there are none")

    monkeypatch.setattr(agent.llm_file_scan, "group_confirm_unverified_findings", exploding)
    agent.node_confirm_triage_groups(state)  # must not raise


def test_node_confirm_triage_groups_calls_confirm_with_expected_args(agent, monkeypatch):
    state = _confirm_state()
    state["_tracer"] = agent.AgentTrace(verbose=False)
    state["usage"] = agent.init_usage(None, None)
    writer = object()
    state["verdict_updates_writer"] = writer

    captured = {}

    def fake_confirm(**kwargs):
        captured.update(kwargs)
        return {
            "candidate_count": 2, "group_count": 1, "confirm_group_count": 1,
            "skipped_group_count": 0, "tp_group_count": 1, "fp_group_count": 0,
            "error_group_count": 0, "confirmed_finding_count": 2,
        }

    monkeypatch.setattr(agent.llm_file_scan, "group_confirm_unverified_findings", fake_confirm)
    result = agent.node_confirm_triage_groups(state)

    assert captured["file_results"] is state["triage_scan_results"]["files"]
    assert captured["verdict_updates_writer"] is writer
    assert captured["usage"] is state["usage"]
    assert captured["group_cap"] == agent.llm_file_scan.TRIAGE_CONFIRM_GROUP_CAP
    assert captured["groups_per_call"] == agent.llm_file_scan.DEFAULT_GROUPS_PER_CALL
    assert result["triage_group_summary"]["confirm_result"]["confirm_group_count"] == 1


def test_node_confirm_triage_groups_respects_state_overrides(agent, monkeypatch):
    state = _confirm_state()
    state["_tracer"] = agent.AgentTrace(verbose=False)
    state["triage_confirm_group_cap"] = 7
    state["triage_confirm_groups_per_call"] = 3

    captured = {}

    def fake_confirm(**kwargs):
        captured.update(kwargs)
        return {
            "candidate_count": 2, "group_count": 1, "confirm_group_count": 1,
            "skipped_group_count": 0, "tp_group_count": 1, "fp_group_count": 0,
            "error_group_count": 0, "confirmed_finding_count": 2,
        }

    monkeypatch.setattr(agent.llm_file_scan, "group_confirm_unverified_findings", fake_confirm)
    agent.node_confirm_triage_groups(state)

    assert captured["group_cap"] == 7
    assert captured["groups_per_call"] == 3


def test_node_confirm_triage_groups_writer_receives_updates(agent, monkeypatch, tmp_path):
    """End-to-end through the real (non-stubbed) group_confirm_unverified_findings
    and its grouping/writer plumbing — only confirm_finding_group's single LLM
    call is faked — to prove the writer contract survives the node boundary."""
    state = _confirm_state()
    state["_tracer"] = agent.AgentTrace(verbose=False)
    state["local_path"] = str(tmp_path)
    state["triage_scan_results"]["files"] = [
        {"file_path": "a.py", "findings": [
            {"rule_id": "secret-password-assign", "line": 1, "severity": "MEDIUM",
             "matched_text": "password = 'hunter2'", "verdict": "unverified",
             "verdict_reason": "not reviewed", "kind": "regex", "confidence": None,
             "file_path": "a.py"},
        ]},
        {"file_path": "b.py", "findings": [
            {"rule_id": "secret-password-assign", "line": 1, "severity": "MEDIUM",
             "matched_text": "password = 'hunter2'", "verdict": "unverified",
             "verdict_reason": "not reviewed", "kind": "regex", "confidence": None,
             "file_path": "b.py"},
        ]},
    ]
    state["triage_scan_results"]["unverified_count"] = 2
    state["triage_group_summary"] = agent.llm_file_scan.group_unverified_findings(
        state["triage_scan_results"]["files"]
    )

    writer_calls = []
    state["verdict_updates_writer"] = lambda file_path, updates: writer_calls.append((file_path, updates))

    def fake_confirm_finding_group(**_kwargs):
        return {
            "verdict": "true_positive", "confidence": 0.9,
            "verdict_reason": "real secret", "ai_fix": None, "error": None,
        }

    monkeypatch.setattr(agent.llm_file_scan, "confirm_finding_group", fake_confirm_finding_group)
    result = agent.node_confirm_triage_groups(state)

    assert {p for p, _ in writer_calls} == {"a.py", "b.py"}
    for _path, updates in writer_calls:
        assert updates[0]["verdict"] == "true_positive"
        assert updates[0]["rule_id"] == "secret-password-assign"
        assert updates[0]["line"] == 1
    assert result["triage_group_summary"]["confirm_result"]["confirm_group_count"] == 1


def test_run_real_scan_end_to_end_no_llm(monkeypatch, project_tree, tmp_path_factory):
    """Regression: exercises agent_bridge's own initial_state construction
    (not just the bare node functions) — this is the path that broke when
    `_tracer` was missing from the state agent_bridge builds."""
    monkeypatch.setenv("SAST_AST_CACHE_DIR", str(tmp_path_factory.mktemp("ast_cache")))
    engine_dir = Path(__file__).resolve().parents[1] / "sast_engine"
    monkeypatch.setattr(settings, "sast_framework_path", str(engine_dir))
    import sys

    sys.modules.pop("sast_scan_agent", None)

    from app.models import Project
    from app.services.agent_bridge import run_real_scan

    project = Project(
        name="bridge-test", default_git_url="https://example.com/repo.git", languages=["Python"]
    )

    class FakeScan:
        llm_provider = None
        llm_model = None
        fallback_llm_provider = None
        fallback_llm_model = None
        metadata_json = {"use_llm": False}

    result = run_real_scan(
        project=project, workspace=project_tree, changed_paths=None, scan_id=None, scan=FakeScan()
    )
    discovery = result["discovery"]
    assert discovery["scan_summary"]["total_files"] == 4
    assert discovery["llm_analysis"]["heuristic_stacks"] == ["python"]
    assert discovery["module_plan"]["risk_counts"]["CRITICAL"] == 2
    assert discovery["report"]["files_scanned"] == 0  # use_llm=False -> nothing scanned
    assert "usage_summary" in result


def test_run_real_scan_threads_confirm_triage_groups(monkeypatch, project_tree, tmp_path_factory):
    """agent_bridge must always enable confirm_triage_groups, uncapped, for
    real scans that use the LLM at all — this is the only path that actually
    reaches the running app (the CLI's --confirm-triage-groups flag, capped
    by default, is a separate opt-in knob for local debugging). Uncapped
    means every unverified group gets confirmed, not just the top-N by
    occurrence, so a real scan never finishes with leftover unverified
    findings short of a doubly-failed LLM call."""
    monkeypatch.setenv("SAST_AST_CACHE_DIR", str(tmp_path_factory.mktemp("ast_cache")))
    engine_dir = Path(__file__).resolve().parents[1] / "sast_engine"
    monkeypatch.setattr(settings, "sast_framework_path", str(engine_dir))
    import sys

    sys.modules.pop("sast_scan_agent", None)

    from app.models import Project
    from app.services import agent_bridge

    real_agent = agent_bridge._load_agent_module()
    captured_states = []

    def fake_invoke_graph(graph, state, **_kwargs):
        captured_states.append(state)
        return {}

    monkeypatch.setattr(real_agent, "invoke_graph", fake_invoke_graph)
    monkeypatch.setattr(agent_bridge, "_load_agent_module", lambda: real_agent)

    project = Project(
        name="bridge-test", default_git_url="https://example.com/repo.git", languages=["Python"]
    )

    class FakeScanUseLlm:
        llm_provider = None
        llm_model = None
        fallback_llm_provider = None
        fallback_llm_model = None
        metadata_json = {"use_llm": True}

    class FakeScanNoLlm(FakeScanUseLlm):
        metadata_json = {"use_llm": False}

    agent_bridge.run_real_scan(
        project=project, workspace=project_tree, changed_paths=None, scan_id=None, scan=FakeScanUseLlm()
    )
    agent_bridge.run_real_scan(
        project=project, workspace=project_tree, changed_paths=None, scan_id=None, scan=FakeScanNoLlm()
    )

    assert captured_states[0]["confirm_triage_groups"] is True
    assert captured_states[0]["triage_confirm_group_cap"] is None  # uncapped — confirm every group
    assert captured_states[1]["confirm_triage_groups"] is False


def test_run_real_scan_threads_scan_limitation_suppression_flags(monkeypatch, project_tree, tmp_path_factory):
    """agent_bridge reads Project.limitations_config for the suppression
    toggles and the inter-file call-graph flag: cwe-less-findings-suppressed
    (default True when unset), https-enforced-suppress-http (default False),
    low-confidence-fp-suppressed (default True), inter-file-call-graph
    (default True, AND use_llm), runtime-derived-regex (default True),
    and Project.max_derived_regex_rules (default 50)."""
    monkeypatch.setenv("SAST_AST_CACHE_DIR", str(tmp_path_factory.mktemp("ast_cache")))
    engine_dir = Path(__file__).resolve().parents[1] / "sast_engine"
    monkeypatch.setattr(settings, "sast_framework_path", str(engine_dir))
    import sys

    sys.modules.pop("sast_scan_agent", None)

    from app.models import Project
    from app.services import agent_bridge

    real_agent = agent_bridge._load_agent_module()
    captured_states = []

    def fake_invoke_graph(graph, state, **_kwargs):
        captured_states.append(state)
        return {}

    monkeypatch.setattr(real_agent, "invoke_graph", fake_invoke_graph)
    monkeypatch.setattr(agent_bridge, "_load_agent_module", lambda: real_agent)

    class FakeScan:
        llm_provider = None
        llm_model = None
        fallback_llm_provider = None
        fallback_llm_model = None
        metadata_json = {"use_llm": True}

    default_project = Project(
        name="bridge-defaults", default_git_url="https://example.com/repo.git", languages=["Python"],
    )
    configured_project = Project(
        name="bridge-configured", default_git_url="https://example.com/repo.git", languages=["Python"],
        limitations_config={
            "cwe-less-findings-suppressed": False,
            "https-enforced-suppress-http": True,
            "low-confidence-fp-suppressed": False,
            "inter-file-call-graph": False,
            "runtime-derived-regex": False,
        },
    )

    agent_bridge.run_real_scan(
        project=default_project, workspace=project_tree, changed_paths=None, scan_id=None, scan=FakeScan()
    )
    agent_bridge.run_real_scan(
        project=configured_project, workspace=project_tree, changed_paths=None, scan_id=None, scan=FakeScan()
    )

    assert captured_states[0]["suppress_no_cwe_findings"] is True
    assert captured_states[0]["suppress_http_findings"] is False
    assert captured_states[0]["suppress_low_confidence_false_positives"] is True
    assert captured_states[0]["inter_file_flow"] is True
    assert captured_states[0]["derive_runtime_rules"] is True
    assert captured_states[0]["max_derived_regex_rules"] == 50
    assert captured_states[1]["suppress_no_cwe_findings"] is False
    assert captured_states[1]["suppress_http_findings"] is True
    assert captured_states[1]["suppress_low_confidence_false_positives"] is False
    assert captured_states[1]["inter_file_flow"] is False
    assert captured_states[1]["derive_runtime_rules"] is False
