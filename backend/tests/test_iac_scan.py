"""Pipeline, container and infrastructure files: the walk keeps .github, the
language tags and risk rules classify them, and the iac.json rules fire on
them through the real scan path (backend/sast_engine/rules/iac.json)."""

import sys
from pathlib import Path

import pytest

pytest.importorskip("langgraph")

from app.config import settings  # noqa: E402
from app.services.agent_bridge import _load_agent_module  # noqa: E402

DOCKERFILE = "FROM node:latest AS build\nUSER root\nENV DB_PASSWORD=hunter2\nRUN curl -fsSL https://x.example/i.sh | sh\n"
WORKFLOW = (
    "name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
    "      - uses: actions/checkout@v4\n"
    "      - uses: docker/build-push-action@v5\n"
    "      - run: echo \"${{ github.event.pull_request.title }}\"\n"
)
TEMPLATE = (
    "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  Db:\n    Type: AWS::RDS::DBInstance\n"
    "    Properties:\n      PubliclyAccessible: true\n      StorageEncrypted: false\n"
)


@pytest.fixture()
def agent(monkeypatch):
    engine_dir = Path(__file__).resolve().parents[1] / "sast_engine"
    monkeypatch.setattr(settings, "sast_framework_path", str(engine_dir))
    sys.modules.pop("sast_scan_agent", None)
    return _load_agent_module()


@pytest.fixture()
def repo(tmp_path):
    (tmp_path / "pom.xml").write_text("<project/>", encoding="utf-8")
    files = {
        "src/main/java/com/acme/Svc.java": "class Svc {}\n",
        "src/main/resources/application.properties": "spring.profiles.active=dev\n",
        "src/main/resources/application.yml": "spring:\n  profiles:\n    active: dev\n",
        "Dockerfile": DOCKERFILE,
        ".github/workflows/ci.yml": WORKFLOW,
        "iac/db.cloudformation.yaml": TEMPLATE,
        ".idea/workspace.xml": "<x/>",
        ".git/config": "[core]",
    }
    for rel, body in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    return tmp_path


def _plan(agent, root):
    state = {
        "local_path": str(root), "scope": None, "context_note": "", "verbose": False,
        "verbose_files": False, "use_llm": False, "persist_to_disk": False,
        "_tracer": agent.AgentTrace(verbose=False),
    }
    state.update(agent.node_scan_directory(state))
    state.update(agent.node_analyze_tech_stack(state))
    state.update(agent.node_categorize_files(state))
    return agent.node_map_modules_and_risk(state)["module_plan"]


def test_walk_keeps_github_but_still_skips_other_dot_directories(agent, repo):
    paths = {f["path"] for f in _plan(agent, repo)["files"]}
    assert ".github/workflows/ci.yml" in paths
    assert not any(p.startswith((".idea/", ".git/")) for p in paths)


def test_pipeline_container_and_template_files_are_classified(agent, repo):
    risk = {f["path"]: f["risk_level"] for f in _plan(agent, repo)["files"]}
    assert risk[".github/workflows/ci.yml"] == "CRITICAL"
    assert risk["Dockerfile"] == "CRITICAL"
    assert risk["iac/db.cloudformation.yaml"] == "CRITICAL"


def test_default_spring_config_files_are_critical(agent, repo):
    """application.properties / application.yml are the files that carry
    spring.profiles.active and the datasource settings; the old pattern only
    matched application-<profile>.* and left them MEDIUM."""
    risk = {f["path"]: f["risk_level"] for f in _plan(agent, repo)["files"]}
    assert risk["src/main/resources/application.properties"] == "CRITICAL"
    assert risk["src/main/resources/application.yml"] == "CRITICAL"


@pytest.mark.parametrize("path,lang", [
    ("Dockerfile", "dockerfile"), ("backend/Dockerfile.prod", "dockerfile"), ("app.dockerfile", "dockerfile"),
    (".github/workflows/ci.yml", "github-actions"), ("sub/.github/workflows/x.yaml", "github-actions"),
    ("iac/db.cloudformation.yaml", "yaml"), ("docker-compose.yml", "yaml"), ("Svc.java", "java"),
])
def test_language_tags(agent, path, lang):
    assert sys.modules["pipeline.llm_file_scan"].lang_for_path(path) == lang


def _rule_ids(agent, path, text):
    regex_scan = sys.modules["pipeline.regex_scan"]
    llm = sys.modules["pipeline.llm_file_scan"]
    rules = regex_scan.load_rules(Path(__file__).resolve().parents[1] / "sast_engine" / "rules")
    hits = regex_scan.scan_text(text, rules, file_lang=llm.lang_for_path(path))
    return {h["rule"] for h in hits}


def test_rules_fire_on_each_file_type(agent):
    assert {"docker-base-image-latest-tag", "docker-user-root", "docker-secret-in-env-or-arg",
            "docker-remote-script-pipe-shell"} <= _rule_ids(agent, "Dockerfile", DOCKERFILE)
    assert {"gha-unpinned-third-party-action", "gha-script-injection"} <= _rule_ids(
        agent, ".github/workflows/ci.yml", WORKFLOW)
    assert {"cfn-resource-publicly-accessible", "cfn-storage-encryption-disabled"} <= _rule_ids(
        agent, "iac/db.cloudformation.yaml", TEMPLATE)


def test_first_party_pinned_and_env_passed_workflows_stay_quiet(agent):
    safe = (
        "on: [push]\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: docker/build-push-action@0123456789abcdef0123456789abcdef01234567\n"
        "      - run: echo \"$TITLE\"\n        env:\n          TITLE: ${{ github.event.pull_request.title }}\n"
    )
    assert _rule_ids(agent, ".github/workflows/ci.yml", safe) == set()


def test_cfn_rules_do_not_fire_on_other_languages_or_egress(agent):
    assert "cfn-resource-publicly-accessible" not in _rule_ids(agent, "notes.txt", TEMPLATE)
    egress = "Resources:\n  Sg:\n    Properties:\n      SecurityGroupEgress:\n        - CidrIp: 0.0.0.0/0\n"
    assert "cfn-ingress-open-to-world" not in _rule_ids(agent, "iac/sg.cloudformation.yaml", egress)


def test_yaml_rules_still_apply_to_workflows(agent):
    rules = sys.modules["pipeline.regex_scan"].load_rules(Path(__file__).resolve().parents[1] / "sast_engine" / "rules")
    yaml_rule = next(r for r in rules if "yaml" in r.languages and "github-actions" not in r.languages)
    assert yaml_rule.applies_to("github-actions", set())
    assert not yaml_rule.applies_to("dockerfile", set())
