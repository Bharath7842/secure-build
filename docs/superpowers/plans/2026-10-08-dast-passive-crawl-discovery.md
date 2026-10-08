# DAST Passive Crawl Discovery Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop DAST crawl extraction from clicking arbitrary page controls while preserving anchor, form, traffic, and script-based discovery.

**Architecture:** Make `extract_links_and_forms` strictly non-interactive by removing its button-click discovery branch. Lock the behavior with a focused fake-page unit regression, a direct real-browser regression that reproduces `EN` → `FR` → `Déconnexion`, and a full-scan regression that proves the crawler does not enter session recovery.

**Tech Stack:** Python 3, pytest, Playwright, local `ThreadingHTTPServer` live fixture.

**Spec:** `docs/superpowers/specs/2026-10-08-dast-passive-crawl-discovery-design.md`

---

## Chunk 1: Regression and fix

### Task 1: Make crawl extraction non-interactive

**File responsibilities:**

- Create `backend/tests/test_dast_crawl.py`: focused unit coverage for crawl link/form extraction. A new file avoids the user's unrelated edits in `test_dast_discovery_domain.py`.
- Modify `backend/tests/dast_fixtures/live_site.py`: model the incident's localized logout control and session-invalidating endpoint.
- Modify `backend/tests/test_dast_live_engine.py`: direct browser and full-scan regressions.
- Modify `backend/app/dast/nodes/crawl.py`: remove active control clicking from extraction.

- [ ] **Step 1: Create the focused extraction fake**

Create `backend/tests/test_dast_crawl.py` with imports, fake elements, and a page fake that exposes a safe anchor, a destructive anchor, a GET form, `EN`, `FR`, and a logout control. Querying the current generic interactive selector must return the controls, and clicking `FR` must localize the logout text.

```python
from __future__ import annotations

import pytest

from app.dast.nodes import crawl as crawl_node

pytestmark = pytest.mark.unit


class _Element:
    def __init__(self, page, *, href=None, text="", control=""):
        self.page = page
        self.href = href
        self.text = text
        self.control = control

    def get_attribute(self, name):
        return self.href if name == "href" else None

    def inner_text(self):
        return self.text

    def is_visible(self):
        return True

    def click(self, **_kwargs):
        self.page.clicks.append(self.control)
        if self.control == "fr":
            self.page.controls[2].text = "Déconnexion"


class _Elements:
    def __init__(self, items):
        self.items = items

    def count(self):
        return len(self.items)

    def nth(self, index):
        return self.items[index]


class _ExtractionPage:
    url = "http://target.test/home"

    def __init__(self):
        self.queried_selectors = []
        self.clicks = []
        self.anchors = [
            _Element(self, href="/employees", text="Employees"),
            _Element(self, href="/delete-all", text="Delete everything"),
        ]
        self.controls = [
            _Element(self, text="EN", control="en"),
            _Element(self, text="FR", control="fr"),
            _Element(self, text="Logout", control="logout"),
        ]

    def locator(self, selector):
        self.queried_selectors.append(selector)
        if selector == "a[href]":
            return _Elements(self.anchors)
        return _Elements(self.controls)

    def wait_for_load_state(self, *_args, **_kwargs):
        return None

    def go_back(self, **_kwargs):
        return None

    def goto(self, *_args, **_kwargs):
        return None

    def eval_on_selector_all(self, selector, _script):
        assert selector == "form"
        return [{"action": "/search", "method": "GET", "inputs": []}]

    def title(self):
        return "Dashboard"
```

- [ ] **Step 2: Add the unit behavior assertion**

Append this test to `backend/tests/test_dast_crawl.py`:

```python
def test_link_and_form_extraction_never_clicks_interactive_controls():
    page = _ExtractionPage()

    title, links, forms = crawl_node.extract_links_and_forms(
        page, "http://target.test/home", "exact"
    )

    assert title == "Dashboard"
    assert links == ["http://target.test/employees"]
    assert forms == [{"action": "/search", "method": "GET", "inputs": []}]
    assert page.queried_selectors == ["a[href]"]
    assert page.clicks == []
```

- [ ] **Step 3: Run the focused unit regression and verify RED**

Run:

```bash
cd backend && .venv/bin/pytest tests/test_dast_crawl.py::test_link_and_form_extraction_never_clicks_interactive_controls -q
```

Expected: FAIL because current code queries `button, [role="link"], [role="button"], [onclick]` and clicks at least `en` and `fr`; the expected selector/click assertions differ.

- [ ] **Step 4: Add the incident controls to the live fixture**

In `backend/tests/dast_fixtures/live_site.py`, replace the `/home` page with an authenticated page containing one normal anchor and exactly three generic buttons:

```python
"/home": """<html><head><title>Dashboard</title></head><body>
<a href='/account'>Account</a>
<button id='en' type='button'>EN</button>
<button id='fr' type='button'>FR</button>
<button id='logout' type='button'>Logout</button>
<script>
document.querySelector('#fr').onclick = () => {
  document.querySelector('#logout').textContent = 'Déconnexion';
};
document.querySelector('#logout').onclick = async () => {
  await fetch('/api/auth/logout', {method: 'POST'});
  location.href = '/login';
};
</script></body></html>""",
```

- [ ] **Step 5: Add the session-invalidating live endpoint**

In `_Handler.do_POST`, before `/api/me`, add:

```python
if path == "/api/auth/logout":
    return self._send(
        204,
        "",
        headers={"Set-Cookie": "session=; Path=/; Max-Age=0; HttpOnly"},
    )
```

- [ ] **Step 6: Add the direct same-context browser regression**

Import `sync_playwright` in `backend/tests/test_dast_live_engine.py` and add:

```python
def test_crawl_extraction_does_not_click_localized_logout_controls():
    with LiveSite() as site, sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            context = browser.new_context()
            page = context.new_page()
            page.goto(f"{site.base}/login")
            page.fill("#u", USER)
            page.fill("#p", PASSWORD)
            page.click("#go")
            page.wait_for_url(f"{site.base}/home")

            crawl_node.extract_links_and_forms(page, site.base, "exact")
            protected_status = page.evaluate(
                "() => fetch('/api/me').then(response => response.status)"
            )
        finally:
            browser.close()

        assert site.paths(method="POST").count("/api/auth/logout") == 0
        assert protected_status == 200
```

This uses one browser context throughout. There is no request guard, so the logout POST would reach the fixture if extraction clicked the localized control.

- [ ] **Step 7: Add the full-scan recovery regression**

Add this separate test to `backend/tests/test_dast_live_engine.py`:

```python
def test_full_crawl_does_not_enter_session_recovery_from_ui_discovery():
    with LiveSite() as site:
        discovery, _audit, _runtime = run(
            site,
            request={
                "method_policy": "opt_in_mutating",
                "target_disposable": True,
            },
        )

        assert "/api/auth/logout" not in site.paths(method="POST")
        assert not discovery.get("authentication_failed")
        assert not any(
            warning.get("event") == "session_lost"
            for warning in discovery.get("warnings", [])
        )
```

- [ ] **Step 8: Run both live regressions and verify RED**

Run:

```bash
cd backend && .venv/bin/pytest -m live \
  tests/test_dast_live_engine.py::test_crawl_extraction_does_not_click_localized_logout_controls \
  tests/test_dast_live_engine.py::test_full_crawl_does_not_enter_session_recovery_from_ui_discovery -q
```

Expected: FAIL. The direct test records `POST /api/auth/logout` and gets 401 from `/api/me`; the full scan records logout and reports a `session_lost` warning or terminal authentication failure.

- [ ] **Step 9: Remove interactive click discovery**

In `backend/app/dast/nodes/crawl.py`:

- remove `INTERACTIVE_SELECTOR`;
- remove `_discover_via_interactive_elements` completely;
- remove `same_domain_links += _discover_via_interactive_elements(...)` from `extract_links_and_forms`;
- update the destructive-filter comment so it refers only to queueing/navigating anchor URLs, not clicking controls.

Keep `_extract_hrefs`, `is_safe_to_visit`, form extraction, network capture, crawl planning, and all downstream discovery unchanged.

- [ ] **Step 10: Re-run the unit regression and verify GREEN**

Run:

```bash
cd backend && .venv/bin/pytest tests/test_dast_crawl.py::test_link_and_form_extraction_never_clicks_interactive_controls -q
```

Expected: `1 passed`.

- [ ] **Step 11: Re-run the live regressions and verify GREEN**

Run the command from Step 8.

Expected: `2 passed`; no logout POST is recorded, the same-context identity probe returns 200, and the full scan has no session-loss warning.

- [ ] **Step 12: Run relevant offline crawl/engine coverage**

Run:

```bash
cd backend && .venv/bin/pytest \
  tests/test_dast_crawl.py \
  tests/test_dast_engine.py \
  tests/test_dast_live_engine.py -q
```

Expected: all selected offline tests pass; live tests are skipped because `-m live` is absent.

- [ ] **Step 13: Run the full live browser module**

Run:

```bash
cd backend && .venv/bin/pytest -m live tests/test_dast_live_engine.py -q
```

Expected: all live browser tests pass.

- [ ] **Step 14: Review and commit only the isolated-worktree changes**

Run `git diff --check`, `git status --short`, and `git diff -- backend/app/dast/nodes/crawl.py backend/tests/test_dast_crawl.py backend/tests/dast_fixtures/live_site.py backend/tests/test_dast_live_engine.py`. The isolated worktree must show only these four implementation files.

Then commit:

```bash
git add backend/app/dast/nodes/crawl.py backend/tests/test_dast_crawl.py backend/tests/dast_fixtures/live_site.py backend/tests/test_dast_live_engine.py
git commit -m "fix: keep DAST crawl discovery non-interactive"
```
