"""Shared pytest configuration.

Markers (registered in pytest.ini): `unit`, `integration`, `live`. The default run is
fully offline: tests marked `live` (they need a real browser, model or practice
target) are skipped unless a `-m` expression names them, e.g. `pytest -m live`.
"""

import pytest

from tests.dast_fixtures import FakeModelGateway, FakeTarget


def pytest_collection_modifyitems(config, items):
    if "live" in (config.getoption("-m") or ""):
        return  # explicitly selected (or explicitly excluded with "not live")
    skip_live = pytest.mark.skip(reason="live test: needs a browser/model/practice target; run with -m live")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip_live)


@pytest.fixture(autouse=True)
def _isolate_dast_screenshots(tmp_path, monkeypatch):
    """Crawl screenshots (DAST) are written to disk under `settings.dast_screenshots_dir` —
    redirect every test to a throwaway directory so the suite never writes into the repo's
    real `data/dast_screenshots/`, regardless of which fake scan_id a test uses."""
    from app.config import settings

    monkeypatch.setattr(settings, "dast_screenshots_dir", str(tmp_path / "dast_screenshots"))


@pytest.fixture(autouse=True)
def _no_joern(tmp_path, monkeypatch):
    """Point JOERN_HOME at an empty dir so a Joern install on the dev machine
    never runs inside the offline suite (joern_runner.joern_available() is
    then False and the Joern graph nodes skip). Live Joern tests undo this."""
    monkeypatch.setenv("JOERN_HOME", str(tmp_path / "no-joern"))


@pytest.fixture()
def fake_target() -> FakeTarget:
    """A fresh in-process web target with an admin and a user account."""
    return FakeTarget()


@pytest.fixture()
def fake_gateway() -> FakeModelGateway:
    """A strict fake model gateway: an unscripted call fails the test."""
    return FakeModelGateway()
