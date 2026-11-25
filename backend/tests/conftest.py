"""Shared pytest configuration.

Markers (registered in pytest.ini): `unit`, `integration`, `live`, `accuracy`. The default
run is fully offline: tests marked `live` (they need a real browser, model or practice
target) are skipped unless a `-m` expression names them, e.g. `pytest -m live`. Tests
marked `accuracy` (the offline accuracy corpus, which scans with the real graph) are
skipped the same way: `pytest -m accuracy`.
"""

import pytest

from tests.dast_fixtures import FakeModelGateway, FakeTarget


def pytest_collection_modifyitems(config, items):
    if "live" not in (config.getoption("-m") or ""):
        skip_live = pytest.mark.skip(reason="live test: needs a browser/model/practice target; run with -m live")
        for item in items:
            if "live" in item.keywords:
                item.add_marker(skip_live)
    if "accuracy" not in (config.getoption("-m") or ""):
        skip_accuracy = pytest.mark.skip(reason="accuracy corpus: run with -m accuracy")
        for item in items:
            if "accuracy" in item.keywords:
                item.add_marker(skip_accuracy)


@pytest.fixture(autouse=True)
def _isolate_dast_screenshots(tmp_path, monkeypatch):
    """Crawl screenshots (DAST) are written to disk under `settings.dast_screenshots_dir` —
    redirect every test to a throwaway directory so the suite never writes into the repo's
    real `data/dast_screenshots/`, regardless of which fake scan_id a test uses."""
    from app.config import settings

    monkeypatch.setattr(settings, "dast_screenshots_dir", str(tmp_path / "dast_screenshots"))


@pytest.fixture(autouse=True)
def _llm_events_off(monkeypatch):
    """The live LLM call log and Langfuse tracing are optional and off by
    default; a developer's LLM_EVENTS_FILE / LANGFUSE_* must never be used by
    the suite. Tests that cover them pass their own context."""
    from app.config import settings

    monkeypatch.setattr(settings, "llm_events_file", "")
    monkeypatch.setattr(settings, "langfuse_host", "")


@pytest.fixture()
def fake_target() -> FakeTarget:
    """A fresh in-process web target with an admin and a user account."""
    return FakeTarget()


@pytest.fixture()
def fake_gateway() -> FakeModelGateway:
    """A strict fake model gateway: an unscripted call fails the test."""
    return FakeModelGateway()
