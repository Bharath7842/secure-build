"""Coverage gaps a reviewer found in a Secure Build report: a committed JWT signing
secret that was never analysed as its own finding, and WebSocket/STOMP subscription
authorisation (as opposed to the allowed-origin list) that was never raised."""

import sys
from pathlib import Path

import pytest

pytest.importorskip("langgraph")

from app.config import settings  # noqa: E402
from app.services.agent_bridge import _load_agent_module  # noqa: E402

_ENGINE_DIR = Path(__file__).resolve().parents[1] / "sast_engine"


@pytest.fixture()
def agent(monkeypatch):
    monkeypatch.setattr(settings, "sast_framework_path", str(_ENGINE_DIR))
    sys.modules.pop("sast_scan_agent", None)
    return _load_agent_module()


def test_websocket_config_is_critical_wherever_it_lives(agent):
    rules = agent.STACK_PROFILES["maven-java"]["rules"]
    for path in (
        "src/main/java/com/acme/config/WebSocketConfig.java",
        "src/main/java/com/acme/messaging/StompBrokerConfig.java",
    ):
        risk, reason, *_ = agent._match_rules(path, rules)
        assert risk == "CRITICAL", path
        assert "WebSocket" in reason


def test_websocket_annotations_are_entry_points(agent):
    for head in ("@EnableWebSocketMessageBroker\nclass A {}", "class B implements WebSocketConfigurer {}"):
        assert agent._ENTRY_CLASS_RE.search(head), head


def test_deep_scan_prompt_names_both_websocket_questions_and_the_redaction_marker():
    from sast_engine.pipeline import llm_file_scan as lfs  # noqa: F401 - import path check
    head = lfs._SYSTEM_HEAD
    assert "SUBSCRIBE" in head and "CWE-306" in head and "setAllowedOrigins" in head
    assert "REDACTED" in head and "signing key" in head
