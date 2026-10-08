"""NODE 3: login - an agentic, step-by-step auth loop that handles both simple and multi-step flows.

Rather than assuming "identify selectors once, then fill+submit", the LLM is given a fresh
summary of the current page's interactive elements each step and decides ONE action at a time
(fill the username, fill the password, click something, wait, or give up). This generalizes to
multi-step logins (username first, then a "Next" click reveals the password field) without any
flow-specific code: the loop just keeps re-observing the page until it looks logged in or the
step budget runs out. Success is checked deterministically after every step (URL left the login
page and no password field remains) rather than trusting the LLM to self-report success.
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Optional

from langgraph.graph import END
from ..domain.session import login_verified, looks_like_login_url
from ..llm_utils import ask_json, print_snippet
from ..state import GraphState

if TYPE_CHECKING:  # lazy: playwright is only needed when a real crawl runs
    from playwright.sync_api import Page

MAX_AUTH_STEPS = 8

FALLBACK_USERNAME_SELECTORS = [
    'input[name="email"]', 'input[id="email" i]', '#email',
    'input[type="email"]', 'input[name="username"]',
    'input[id*="email" i]', 'input[id*="user" i]',
]
FALLBACK_PASSWORD_SELECTOR = 'input[type="password"]'
FALLBACK_SUBMIT_SELECTORS = [
    'button[type="submit"]', 'input[type="submit"]', '#loginButton',
    'button:has-text("Log in")', 'button:has-text("Login")', 'button:has-text("Sign in")',
]


AUTH_ACTION_TYPES = ["fill_username", "fill_password", "click", "wait", "give_up"]

# The reply the `login_selectors` model task returns each step: the single next action. `selector`
# is a CSS selector the browser can use directly, required for fill_username/fill_password/click.
AUTH_ACTION_SCHEMA = {
    "type": "object",
    "required": ["action_type"],
    "properties": {
        "action_type": {"type": "string", "enum": AUTH_ACTION_TYPES},
        "selector": {"type": ["string", "null"]},
        "reason": {"type": "string", "maxLength": 200},
    },
}


def extract_interactive_elements(page: Page) -> str:
    """Summarize visible input/button/link elements for the LLM to choose an action against.

    Uses Playwright locators (which pierce open shadow roots) rather than a raw
    querySelectorAll, so fields rendered inside web components aren't invisible to the agent.
    """
    elements = []
    try:
        combined = page.locator('input, button, a[role="button"], [role="link"], [onclick]')
        count = min(combined.count(), 40)
        for i in range(count):
            try:
                el = combined.nth(i)
                if not el.is_visible():
                    continue
                tag = el.evaluate("e => e.tagName.toLowerCase()")
                text = (el.inner_text() or el.get_attribute("value") or "").strip()[:60]
                elements.append({
                    "tag": tag,
                    "type": el.get_attribute("type"),
                    "id": el.get_attribute("id"),
                    "name": el.get_attribute("name"),
                    "text": text,
                })
            except Exception:  # noqa: BLE001
                continue
    except Exception:  # noqa: BLE001
        pass
    return json.dumps(elements)


_POST_LOGIN_INDICATORS = (
    'a:has-text("Log out")', 'a:has-text("Logout")', 'a:has-text("Sign out")',
    'button:has-text("Log out")', 'button:has-text("Logout")', 'button:has-text("Sign out")',
    'a[href*="logout" i]', 'a[href*="signout" i]', '[data-testid*="logout" i]',
)


def _url_left_login(current: str, login_url: str) -> bool:
    """True when the browser left the login route. Hash-routed SPAs keep the same path (`/`) and
    only change `#/login` → `#/search`, so a string inequality is not enough on its own — staying
    on another login-shaped URL (wrong password) must not count."""
    if not login_url or not current:
        return False
    if current.rstrip("/") == login_url.rstrip("/"):
        return False
    return not looks_like_login_url(current)


def _visible_password_present(page: Page) -> bool:
    try:
        fields = page.locator('input[type="password"]')
        for i in range(fields.count()):
            if fields.nth(i).is_visible():
                return True
    except Exception:  # noqa: BLE001
        return False
    return False


def wait_for_left_login(page: Page, login_url: str, timeout: int = 8_000) -> None:
    """SPA logins change `location.hash` without a document load; `networkidle` returns too early."""
    try:
        page.wait_for_function(
            """login => {
                const href = location.href;
                if (!login || href === login) return false;
                const path = location.pathname + location.hash;
                return !/(\\/|#\\/)(log[-_]?in|sign[-_]?in|signin)\\b/i.test(path);
            }""",
            arg=login_url,
            timeout=timeout,
        )
    except Exception:  # noqa: BLE001
        pass


def login_signals(page: Page, login_url: str) -> list[str]:
    """The independent signs that a login worked: the page left the login URL, no password field
    remains, a signed-in marker (a log-out control) is present. One of them alone is not proof
    (an error page also changes the URL); `domain.session.login_verified` needs two."""
    signals: list[str] = []
    try:
        if _url_left_login(page.url, login_url):
            signals.append("url_changed")
        if not _visible_password_present(page):
            signals.append("credential_field_gone")
        for selector in _POST_LOGIN_INDICATORS:
            if page.locator(selector).count() > 0:
                signals.append("post_login_indicator")
                break
    except Exception:  # noqa: BLE001
        pass
    return signals


def looks_logged_in(page: Page, login_url: str) -> bool:
    """Generic, app-agnostic success/session heuristic: at least two independent signals (see
    `login_signals`). Used both to end the login loop and, by the crawl node, as a session
    "heartbeat" to detect getting bounced back to a login screen mid-crawl."""
    if not login_url:
        return False
    return login_verified(login_signals(page, login_url))


def dismiss_overlays(page: Page) -> None:
    """Best-effort dismissal of blocking modals/banners (cookie consent, ads, welcome dialogs, etc.)."""
    try:
        page.keyboard.press("Escape")
    except Exception:  # noqa: BLE001
        pass
    # Prefer labelled controls. Avoid `button:has-text("Close")` — Juice Shop's search-close
    # matches that and intercepts the click while the welcome dialog is still up.
    dismiss_selectors = [
        'button[aria-label="Close Welcome Banner"]',
        'a[aria-label="dismiss cookie message"]',
        'a:has-text("Me want it!")',
        'button:has-text("Dismiss")',
        'button:has-text("Accept")',
        '[aria-label="Close" i]',
        ".cdk-overlay-backdrop",
    ]
    for _ in range(4):
        clicked = False
        for sel in dismiss_selectors:
            try:
                locator = page.locator(sel)
                if locator.count() > 0 and locator.first.is_visible():
                    locator.first.click(timeout=1_000, force=True)
                    clicked = True
                    break
            except Exception:  # noqa: BLE001
                continue
        if not clicked:
            return


def click_with_retry(page: Page, selector: str, attempts: int = 10) -> None:
    """Click a selector, retrying past transient overlay interception (cookie/ad banners, etc.).

    A plain retry of the same click is pointless if a persistent overlay is
    covering the target the whole time (Playwright's own internal actionability
    retries already exhaust that within a single click() call). Each attempt
    here first tries to dismiss known overlay patterns, then falls back to a
    force click that bypasses the interception check entirely.
    """
    last_error: Optional[Exception] = None
    for _ in range(attempts):
        dismiss_overlays(page)
        try:
            page.click(selector, timeout=3_000)
            return
        except Exception as exc:  # noqa: BLE001
            last_error = exc
        try:
            page.click(selector, timeout=2_000, force=True)
            return
        except Exception as exc:  # noqa: BLE001
            last_error = exc
        time.sleep(0.5)
    raise last_error


def open_login_page(page: Page, login_url: str) -> None:
    """Load the login URL and wait for a client-rendered form. Hash-routed SPAs (Juice Shop
    `#/login`) ship an empty shell first; waiting only for any `input` matches the search box
    on the homepage before the route has rendered."""
    page.goto(login_url, timeout=10_000)
    try:
        page.wait_for_selector(
            'input[type="password"], input[name="email"], input[type="email"], #email, form, input',
            timeout=8_000,
        )
    except Exception:  # noqa: BLE001
        pass
    dismiss_overlays(page)


def simple_form_selectors(page: Page) -> Optional[dict]:
    """Username, password and submit if a one-page login form is actually on screen."""
    username = find_first_matching_selector(page, FALLBACK_USERNAME_SELECTORS)
    submit = find_first_matching_selector(page, FALLBACK_SUBMIT_SELECTORS)
    try:
        password_present = page.locator(FALLBACK_PASSWORD_SELECTOR).count() > 0
    except Exception:  # noqa: BLE001
        password_present = False
    if username and password_present and submit:
        return {"username_selector": username, "password_selector": FALLBACK_PASSWORD_SELECTOR, "submit_selector": submit}
    return None


def find_first_matching_selector(page: Page, selectors: list) -> Optional[str]:
    for sel in selectors:
        try:
            if page.locator(sel).count() > 0:
                return sel
        except Exception:  # noqa: BLE001
            continue
    return None


def attempt_fill_and_submit(page: Page, username: str, password: str, selectors: dict) -> None:
    print(f"    Executing: page.fill('{selectors['username_selector']}', '<username>')")
    page.fill(selectors["username_selector"], username, timeout=5_000)
    print(f"    Executing: page.fill('{selectors['password_selector']}', '********')")
    page.fill(selectors["password_selector"], password, timeout=5_000)
    # Angular/Material keeps Log in disabled until both fields validate; a force-click is a no-op.
    try:
        page.wait_for_function(
            """sel => {
                const el = document.querySelector(sel);
                return !!el && !el.disabled && el.getAttribute('aria-disabled') !== 'true';
            }""",
            arg=selectors["submit_selector"],
            timeout=5_000,
        )
    except Exception:  # noqa: BLE001
        pass
    print(f"    Executing: page.click('{selectors['submit_selector']}')")
    click_with_retry(page, selectors["submit_selector"])


def verify_login_success(
    page: Page,
    success_indicator: str,
    login_url: str,
    used_fallback_url_check: bool,
    username_selector: str = "",
    password_selector: str = "",
) -> bool:
    if used_fallback_url_check:
        try:
            page.wait_for_function(
                "url => window.location.href !== url",
                arg=login_url,
                timeout=8_000,
            )
            return True
        except Exception:  # noqa: BLE001
            return False

    try:
        page.wait_for_selector(success_indicator, timeout=8_000)
        return True
    except Exception:  # noqa: BLE001
        pass
    try:
        page.get_by_text(success_indicator).wait_for(timeout=8_000)
        return True
    except Exception:  # noqa: BLE001
        pass
    try:
        page.wait_for_function(
            "url => window.location.href !== url",
            arg=login_url,
            timeout=5_000,
        )
        return True
    except Exception:  # noqa: BLE001
        pass
    try:
        page.wait_for_selector(username_selector, state="detached", timeout=3_000)
        page.wait_for_selector(password_selector, state="detached", timeout=1_000)
        return True
    except Exception:  # noqa: BLE001
        return False


def _fallback_single_shot_login(state: GraphState) -> GraphState:
    """Deterministic single-shot login, used only if the LLM is unreachable on the very first step.

    Only handles the simple_form shape (fill both fields, click submit, done) - it has no way to
    discover a multi-step flow without the LLM guiding it - but it's a better-than-nothing safety
    net against a total Ollama outage rather than failing immediately.
    """
    print("    LLM unreachable on first step; falling back to hardcoded selector heuristics (simple_form only).")
    page = state["page"]
    username_sel = find_first_matching_selector(page, FALLBACK_USERNAME_SELECTORS)
    submit_sel = find_first_matching_selector(page, FALLBACK_SUBMIT_SELECTORS)
    state["identified_username_selector"] = username_sel or FALLBACK_USERNAME_SELECTORS[0]
    state["identified_password_selector"] = FALLBACK_PASSWORD_SELECTOR
    state["identified_submit_selector"] = submit_sel or FALLBACK_SUBMIT_SELECTORS[0]
    state["identified_success_indicator"] = ""
    state["selector_source"] = "fallback"

    try:
        attempt_fill_and_submit(page, state["username"], state["password"], {
            "username_selector": state["identified_username_selector"],
            "password_selector": state["identified_password_selector"],
            "submit_selector": state["identified_submit_selector"],
        })
        # A URL change alone is a single weak signal; also require a second one.
        wait_for_left_login(page, state["login_url"])
        success = verify_login_success(
            page, "", state["login_url"], True,
            username_selector=state["identified_username_selector"],
            password_selector=state["identified_password_selector"],
        ) and looks_logged_in(page, state["login_url"])
    except Exception as exc:  # noqa: BLE001
        state["login_error"] = str(exc)
        success = False

    state["login_success"] = success
    if success:
        state["crawl_start_url"] = page.url
        print("[3/4] Attempting login ... SUCCESS (selector_source: fallback)")
    else:
        if not state["login_error"]:
            state["login_error"] = "Fallback login attempted but success indicator was not detected."
        print(f"[3/4] Attempting login ... FAILED ({state['login_error']}, selector_source: fallback)")
    return state


def login(state: GraphState) -> GraphState:
    verbose = state.get("verbose", True)
    page = state["page"]
    print("[3/4] Starting agentic login (handles simple and multi-step flows)...")
    dismiss_overlays(page)

    done: list[str] = []  # actions already taken this attempt; the page alone does not show them
    for step in range(1, MAX_AUTH_STEPS + 1):
        dom_summary = extract_interactive_elements(page)
        print_snippet(f"Interactive elements (step {step}/{MAX_AUTH_STEPS})", dom_summary, verbose)

        prompt = f"""You are logging into a web application, one step at a time.

Current page URL: {page.url}
Username to use: {state['username']}
(the password is available to fill but not shown here)

Actions you have ALREADY taken on this login, in order (do not repeat one; move to the next step):
{chr(10).join(f"{i}. {a}" for i, a in enumerate(done, 1)) if done else "(none yet)"}
Typical order: fill_username, then fill_password, then click the sign-in button.

Visible interactive elements on the current page, as JSON:
{dom_summary}

Decide the SINGLE next action:
- fill_username: fill the username/email field (selector required)
- fill_password: fill the password field (selector required, only if a password field is visible now)
- click: click a button/link to proceed, e.g. "Next", "Continue", "Sign in" (selector required)
- wait: take no action this step (e.g. the page still looks like it's loading)
- give_up: nothing more can be done (e.g. this isn't actually a login form, or you're stuck)

The selector must be a CSS selector Playwright can use directly (e.g. "#email",
"input[name='username']", "button[type='submit']").

Respond with JSON only, exactly one decision:
{{"action_type": "<one of the actions above>", "selector": "<CSS selector or null>", "reason": "<short reason>"}}
"""
        decision = ask_json(state["gateway"], "login_selectors", prompt, AUTH_ACTION_SCHEMA)

        if decision is None:
            if step == 1:
                return _fallback_single_shot_login(state)
            state["login_error"] = "Agentic login: LLM call failed after retries"
            break

        action_type = decision.get("action_type")
        selector = decision.get("selector")
        reason = decision.get("reason") or ""
        print(f"    [auth-agent] step {step}/{MAX_AUTH_STEPS}: {action_type} {selector or ''} — {reason}")

        if action_type in ("fill_username", "fill_password", "click") and selector:
            entry = f"{action_type} {selector}"
            if entry in done:  # the model repeated itself: say so rather than loop to the step limit
                print(f"    [auth-agent] repeated action ignored: {entry}")
                done.append(f"{entry} (repeated; this did nothing new)")
                continue
            done.append(entry)

        if action_type == "give_up":
            wait_for_left_login(page, state["login_url"])
            if looks_logged_in(page, state["login_url"]):
                state["login_success"] = True
                state["selector_source"] = "llm"
                state["identified_success_indicator"] = "(generic: left login URL, no password field remains)"
                state["crawl_start_url"] = page.url
                print(f"[3/4] Agentic login SUCCESS after {step} step(s) (model reported done; page is signed in)")
                return state
            filled = any(a.startswith("fill_password") or a.startswith("click ") for a in done)
            if not filled and simple_form_selectors(page) and _fallback_single_shot_login(state).get("login_success"):
                return state
            state["login_error"] = reason or "LLM chose to give up on this login flow"
            break

        try:
            if action_type == "fill_username" and selector:
                print(f"    Executing: page.fill('{selector}', '<username>')")
                page.fill(selector, state["username"], timeout=5_000)
                state["identified_username_selector"] = selector
            elif action_type == "fill_password" and selector:
                print(f"    Executing: page.fill('{selector}', '********')")
                page.fill(selector, state["password"], timeout=5_000)
                state["identified_password_selector"] = selector
            elif action_type == "click" and selector:
                print(f"    Executing: page.click('{selector}')")
                click_with_retry(page, selector)
                state["identified_submit_selector"] = selector
                wait_for_left_login(page, state["login_url"])
            elif action_type == "wait":
                page.wait_for_timeout(1_000)
        except Exception as exc:  # noqa: BLE001
            print(f"    [auth-agent] action failed: {exc}")
            # Keep looping - the next step's fresh DOM summary gives the LLM a chance to recover.

        if looks_logged_in(page, state["login_url"]):
            state["login_success"] = True
            state["selector_source"] = "llm"
            state["identified_success_indicator"] = "(generic: left login URL, no password field remains)"
            state["crawl_start_url"] = page.url
            print(f"[3/4] Agentic login SUCCESS after {step} step(s)")
            return state

    state["login_success"] = False
    if not state.get("login_error"):
        state["login_error"] = f"Agentic login did not reach a verified success state within {MAX_AUTH_STEPS} steps"
    print(f"[3/4] Agentic login FAILED: {state['login_error']}")
    return state


def route_after_login(state: GraphState) -> str:
    """Conditional routing: only proceed to crawl if login actually succeeded."""
    return "crawl" if state["login_success"] else END
