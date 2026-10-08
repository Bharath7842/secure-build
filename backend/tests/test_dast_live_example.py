"""Template for a `live` test (needs a browser, a model or a practice target).

Skipped in the default run; select with `pytest -m live`. EPIC-16 replaces this
with real practice-target tests — keep one example here so the skip behaviour
stays covered by `test_dast_fixtures.py`.
"""

import pytest


@pytest.mark.live
def test_live_marker_example():
    assert True
