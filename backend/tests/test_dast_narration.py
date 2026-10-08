"""Unit tests for app.services.dast_narration's text-extraction helpers.

These guard against two real bugs seen in production: raw, unparsed model
JSON (or its scaffolding/preamble) reaching the screen, and a running step's
"working on it" line picking up raw log noise (print_snippet dumps, engine
[thinking]/[planner] chatter, page.fill()/page.goto() traces) instead of a
clean progress banner.
"""

import threading
import time

from app.services import dast_narration


def test_parse_narration_response_extracts_narration_and_reasoning():
    raw = '{"narration": "I signed in successfully.", "reasoning": ["Confirmed via a redirect to /dashboard."]}'
    result = dast_narration.parse_narration_response(raw)
    assert result == {
        "narration": "I signed in successfully.",
        "reasoning": ["Confirmed via a redirect to /dashboard."],
    }


def test_parse_narration_response_rejects_truncated_json():
    # Exactly the shape a still-in-progress stream looks like mid-generation —
    # must never be treated as a valid, displayable result.
    raw = '{"narration": "We need to classify the login page... So output JSON: {"login_type":"simple_form","reason":"single page with'
    assert dast_narration.parse_narration_response(raw) is None


def test_parse_narration_response_rejects_wrong_schema():
    # Valid JSON, but not our schema (e.g. the model echoed the underlying
    # classify_login_type task's own {"login_type", "reason"} shape instead).
    raw = '{"login_type": "simple_form", "reason": "single page with email/password"}'
    assert dast_narration.parse_narration_response(raw) is None


def test_parse_narration_response_rejects_empty_and_none():
    assert dast_narration.parse_narration_response("") is None
    assert dast_narration.parse_narration_response("not json at all") is None


def test_running_text_picks_progress_banner_not_raw_log_noise():
    evidence = [
        "[2/4] Extracting login page details and classifying login type...",
        '    [Extracted page_details sent to LLM]',
        '    {"forms": [{"inputs": [{"name": null, "type": "email", "id": "email"}]}]}',
        "    [thinking] We need to classify the login page. The page signals: forms:...",
        '[2/4] Classification: simple_form (reason: \'single page with email/password\')',
        "[3/4] Starting agentic login (handles simple and multi-step flows)...",
        "    Executing: page.fill('#email', 'admin')",
        "    [auth-agent] step 1/8: fill #email",
    ]
    assert dast_narration._running_text("auth", evidence, None) == "step 1/8: fill #email."


def test_running_text_falls_back_when_no_progress_banner_yet():
    assert (
        dast_narration._running_text("auth", ["    Executing: page.goto('http://x/login')"], None)
        == "Inspecting the login page and signing in."
    )


# ---- thinking vs. reasoning split -----------------------------------------------------------------------------


def test_thinking_from_log_pulls_full_scratchpad_not_just_a_snippet():
    long_thought = "We need to decide. " + ("x" * 500)
    evidence = [
        f"    [thinking] {long_thought}",
        "    [planner] Chose /admin — reason: 'looks interesting'",
        f"    [thinking] {long_thought}",  # duplicate, must collapse
    ]
    thinking = dast_narration._thinking_from_log(evidence)
    assert thinking == [long_thought[:2000], "Chose /admin — reason: 'looks interesting'"]
    # the old 400-char reasoning extractor is unaffected / still available to callers
    assert dast_narration._reasoning_from_log(evidence)[0] == long_thought[:400]


def test_is_scratchpad_flags_raw_chain_of_thought_not_finished_bullets():
    assert dast_narration._is_scratchpad("We need to output JSON with shape, auth, schema")
    assert dast_narration._is_scratchpad("We have a form with inputs: email, password")
    # cut off mid-word with no terminal punctuation, at the legacy 400-char truncation
    assert dast_narration._is_scratchpad("x" * 395)
    assert not dast_narration._is_scratchpad("A successful response confirms the application is up.")
    assert not dast_narration._is_scratchpad("")


def test_clean_reasoning_drops_scratchpad_entries_only():
    mixed = [
        "Connection returned HTTP 200, proving the host is up.",
        "We need to output JSON with shape, auth, schema, reason. The evidence says root_content_type"
        " text/html, root_body_excerpt shows HTML with <html> etc. But the content includes a script",
        "The fingerprint indicates a SPA.",
    ]
    assert dast_narration._clean_reasoning(mixed) == [
        "Connection returned HTTP 200, proving the host is up.",
        "The fingerprint indicates a SPA.",
    ]


def test_get_narration_separates_thinking_from_reasoning_and_sanitizes_legacy_persisted_reasoning(monkeypatch):
    monkeypatch.setattr(dast_narration, "_llm_enabled", lambda: False)
    lines = [
        "### DAST: checking connection",
        "    [thinking] We need to decide if this is reachable based on the response code",
        "  checking connection: working",
    ]
    # Simulate a scan persisted before thinking/reasoning were split: its
    # reasoning array still carries raw scratchpad text.
    persisted = {
        "connection": {
            "fingerprint": dast_narration._fingerprint(
                [l for l in lines if not l.strip().startswith("### DAST:")], None, "connection"
            ),
            "narration": "I confirmed the target is reachable.",
            "reasoning": [
                "Connection returned HTTP 200.",
                "We need to output JSON with shape, auth, schema, reason. The evidence says root_content_type"
                " text/html and more detail that trails off without a period",
            ],
            "source": "llm",
        }
    }
    payload = dast_narration.get_narration("legacy-scan", "success", lines, None, {}, persisted=persisted)
    step = next(s for s in payload["steps"] if s["id"] == "connection")
    assert step["reasoning"] == ["Connection returned HTTP 200."]
    assert any("We need to decide" in t for t in step["thinking"])
    assert "We need to decide" not in " ".join(step["reasoning"])


def test_get_narration_returns_full_evidence_not_just_the_last_60_lines(monkeypatch):
    monkeypatch.setattr(dast_narration, "_llm_enabled", lambda: False)
    many_lines = [f"  line {i}" for i in range(120)]
    lines = ["### DAST: testing apis", *many_lines]
    payload = dast_narration.get_narration("big-log-scan", "success", lines, None, {})
    step = next(s for s in payload["steps"] if s["id"] == "testing")
    assert len(step["evidence"]) == 120
    assert step["evidence"][0] == "  line 0" and step["evidence"][-1] == "  line 119"


# ---- running-step narration is bucketed, not re-called on every poll -----------------------------------------


def test_running_step_narration_is_bucketed_not_recomputed_every_poll(monkeypatch):
    calls: list[str] = []

    def fake_call_llm(prompt):
        calls.append(prompt)
        return {"narration": f"call {len(calls)}", "reasoning": []}

    monkeypatch.setattr(dast_narration, "_llm_enabled", lambda: True)
    monkeypatch.setattr(dast_narration, "_call_llm", fake_call_llm)

    def make_lines(n_evidence: int) -> list[str]:
        return ["### DAST: testing apis", *[f"  [{i}/999] Testing something" for i in range(n_evidence)]]

    def wait_for_bucket(scan_id: str, lines: list[str]) -> dict:
        # Background threads populate the cache asynchronously; poll briefly.
        for _ in range(50):
            payload = dast_narration.get_narration(scan_id, "running", lines, None, {})
            step = next(s for s in payload["steps"] if s["id"] == "testing")
            if step["source"] == "llm":
                return step
            time.sleep(0.01)
        return step

    first = wait_for_bucket("bucket-scan", make_lines(5))
    assert first["source"] == "llm"
    calls_after_first = len(calls)

    # Still inside the same bucket (< _RUNNING_NARRATION_BUCKET_LINES new lines) — no new call.
    again = wait_for_bucket("bucket-scan", make_lines(6))
    assert again["narration"] == first["narration"]
    assert len(calls) == calls_after_first

    # Enough new evidence to cross into the next bucket — a fresh call.
    grown = wait_for_bucket("bucket-scan", make_lines(6 + dast_narration._RUNNING_NARRATION_BUCKET_LINES))
    assert len(calls) > calls_after_first
    assert grown["narration"] != first["narration"]


def test_get_narration_starts_only_one_llm_at_a_time(monkeypatch):
    dast_narration._cache.clear()
    dast_narration._inflight.clear()
    started: list[str] = []
    gate = threading.Semaphore(0)

    def fake_call_llm(prompt):
        started.append(prompt[:40])
        assert gate.acquire(timeout=2)
        return {"narration": f"n{len(started)}", "reasoning": ["ok"]}

    monkeypatch.setattr(dast_narration, "_llm_enabled", lambda: True)
    monkeypatch.setattr(dast_narration, "_call_llm", fake_call_llm)

    lines = [
        "### DAST: checking connection",
        "  connection ok",
        "### DAST: logging in",
        "  logged in",
        "### DAST: crawling",
        "  crawled",
    ]
    payload = dast_narration.get_narration("seq-scan", "success", lines, None, {"target_url": "http://x"})
    time.sleep(0.05)
    assert len(started) == 1
    assert payload["pending"] is True
    assert payload["intro_source"] is None
    conn = next(s for s in payload["steps"] if s["id"] == "connection")
    assert conn.get("narration_pending") is True

    gate.release()
    for _ in range(50):
        if dast_narration.get_narration("seq-scan", "success", lines, None, {"target_url": "http://x"}).get("intro_source") == "llm":
            break
        time.sleep(0.01)
    else:
        raise AssertionError("intro narration never cached")
    time.sleep(0.05)
    second = dast_narration.get_narration("seq-scan", "success", lines, None, {"target_url": "http://x"})
    time.sleep(0.05)
    assert len(started) == 2  # intro finished, then connection — not auth/discovery yet
    conn = next(s for s in second["steps"] if s["id"] == "connection")
    assert conn.get("narration_pending") is True
    auth = next(s for s in second["steps"] if s["id"] == "auth")
    assert auth.get("narration_pending") is True
    assert auth.get("source") is None
    gate.release()
    dast_narration._inflight.clear()
