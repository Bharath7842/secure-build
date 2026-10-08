"""Coverage for the AST structural pass (backend/sast_engine/ast_struct.py)
that feeds annotation counts / entry points / route-guard coverage into the
"Detecting Tech Stack" step, plus its wiring into node_analyze_tech_stack.
"""

from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_java")
pytest.importorskip("tree_sitter_typescript")
pytest.importorskip("langgraph")

from app.config import settings  # noqa: E402
from app.services.agent_bridge import _load_agent_module  # noqa: E402

JAVA_CONTROLLER = """
package com.example;

@RestController
@RequestMapping("/api")
public class FooController {
    @GetMapping("/foo")
    @PreAuthorize("hasRole('ADMIN')")
    public String foo() { return "x"; }

    @PostMapping("/bar")
    public String bar() { return "y"; }
}
"""

JAVA_ENTITY = """
package com.example;

@Entity
public class Widget {}
"""

JAVA_REPO_SERVICE = """
package com.example;

@Repository
interface WidgetRepository {}
"""

TS_COMPONENT = """
import { Component } from "@angular/core";

@Component({ selector: "app-foo" })
export class FooComponent {}
"""

TS_SERVICE = """
import { Injectable } from "@angular/core";

@Injectable({ providedIn: "root" })
export class FooService {}
"""

TS_ROUTES = """
import { Routes } from "@angular/router";
import { AuthGuard } from "./auth.guard";

export const routes: Routes = [
  { path: "admin", component: FooComponent, canActivate: [AuthGuard] },
  { path: "public", component: FooComponent },
];
"""


@pytest.fixture()
def agent(monkeypatch):
    import sys

    engine_dir = Path(__file__).resolve().parents[1] / "sast_engine"
    monkeypatch.setattr(settings, "sast_framework_path", str(engine_dir))
    sys.modules.pop("sast_scan_agent", None)
    sys.modules.pop("ast_struct", None)
    return _load_agent_module()


@pytest.fixture()
def ast_struct(agent):
    import sys

    return sys.modules["ast_struct"]


@pytest.fixture()
def maven_angular_tree(tmp_path):
    controllers = tmp_path / "src/main/java/com/example/controller"
    controllers.mkdir(parents=True)
    (controllers / "FooController.java").write_text(JAVA_CONTROLLER, encoding="utf-8")

    model = tmp_path / "src/main/java/com/example/model"
    model.mkdir(parents=True)
    (model / "Widget.java").write_text(JAVA_ENTITY, encoding="utf-8")

    repo = tmp_path / "src/main/java/com/example/repository"
    repo.mkdir(parents=True)
    (repo / "WidgetRepository.java").write_text(JAVA_REPO_SERVICE, encoding="utf-8")

    (tmp_path / "pom.xml").write_text("<project></project>\n", encoding="utf-8")

    ng_src = tmp_path / "frontend/src/app"
    ng_src.mkdir(parents=True)
    (ng_src / "foo.component.ts").write_text(TS_COMPONENT, encoding="utf-8")
    (ng_src / "foo.service.ts").write_text(TS_SERVICE, encoding="utf-8")
    (ng_src / "app.routes.ts").write_text(TS_ROUTES, encoding="utf-8")
    (tmp_path / "frontend/angular.json").parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / "frontend/angular.json").write_text("{}\n", encoding="utf-8")

    return tmp_path


# ---------------------------------------------------------------------------
# Unit-level: per-file extraction
# ---------------------------------------------------------------------------


def test_analyze_java_source_counts_annotations_and_entry_points(ast_struct):
    counts, entry_points = ast_struct.analyze_java_source("FooController.java", JAVA_CONTROLLER)
    assert counts["RestController"] == 1

    assert len(entry_points) == 2
    by_method = {e["method"]: e for e in entry_points}
    assert by_method["foo"]["verb"] == "GET"
    assert by_method["foo"]["path"] == "/api/foo"
    assert by_method["foo"]["authorized"] is True
    assert by_method["bar"]["verb"] == "POST"
    assert by_method["bar"]["authorized"] is False


def test_analyze_ts_source_counts_decorators_bare_and_exported(ast_struct):
    # exported class — decorator is a sibling under export_statement
    dec, _, _ = ast_struct.analyze_ts_source("foo.component.ts", TS_COMPONENT)
    assert dec["Component"] == 1

    # also exported here, but exercise the bare-class nesting shape directly
    bare_src = TS_SERVICE.replace("export class", "class")
    dec2, _, _ = ast_struct.analyze_ts_source("foo.service.ts", bare_src)
    assert dec2["Injectable"] == 1


def test_analyze_ts_source_finds_routes_and_guard_coverage(ast_struct):
    _, _, routes = ast_struct.analyze_ts_source("app.routes.ts", TS_ROUTES)
    by_path = {r["path"]: r["guarded"] for r in routes}
    assert by_path == {"admin": True, "public": False}


# ---------------------------------------------------------------------------
# build_ast_summary — full pass across a small on-disk project
# ---------------------------------------------------------------------------


def test_build_ast_summary_across_maven_and_angular(agent, ast_struct, maven_angular_tree):
    state = {
        "local_path": str(maven_angular_tree),
        "scope": None,
        "context_note": "",
        "verbose": False,
        "verbose_files": False,
        "use_llm": False,
        "persist_to_disk": False,
        "_tracer": agent.AgentTrace(verbose=False),
    }
    scan = agent.node_scan_directory(state)["scan"]
    heuristic_stacks = agent.detect_stacks_heuristic(scan)
    assert set(heuristic_stacks) >= {"maven-java", "angular"}

    summary = ast_struct.build_ast_summary(scan, heuristic_stacks, maven_angular_tree)
    assert summary is not None

    mj = summary["stacks"]["maven-java"]
    assert mj["annotations"]["RestController"] == 1
    assert mj["annotations"]["Entity"] == 1
    assert mj["annotations"]["Repository"] == 1
    assert mj["entry_point_count"] == 2
    assert mj["unauthenticated_entry_points"] == 1

    ng = summary["stacks"]["angular"]
    assert ng["decorators"]["Component"] == 1
    assert ng["decorators"]["Injectable"] == 1
    assert ng["route_count"] == 2
    assert ng["unguarded_route_count"] == 1

    risk_areas = ast_struct.structural_risk_areas(summary)
    assert any("REST endpoint" in a for a in risk_areas)
    assert any("JPA entit" in a for a in risk_areas)
    assert any("Angular route" in a for a in risk_areas)

    prompt_block = ast_struct.format_ast_summary_for_prompt(summary)
    assert "RestController" in prompt_block
    assert "UNAUTHENTICATED" in prompt_block


def test_node_analyze_tech_stack_includes_ast_summary_without_llm(agent, maven_angular_tree):
    state = {
        "local_path": str(maven_angular_tree),
        "scope": None,
        "context_note": "",
        "verbose": False,
        "verbose_files": False,
        "use_llm": False,
        "persist_to_disk": False,
        "_tracer": agent.AgentTrace(verbose=False),
    }
    state.update(agent.node_scan_directory(state))
    result = agent.node_analyze_tech_stack(state)
    llm_analysis = result["llm_analysis"]

    assert llm_analysis["llm_used"] is False
    assert llm_analysis["ast_summary"] is not None
    assert llm_analysis["confidence"] == "high"  # real AST signal (entry points + decorators found)
    assert llm_analysis["project_type"] == "web app"
    assert any("REST endpoint" in a for a in llm_analysis["risk_areas"])
