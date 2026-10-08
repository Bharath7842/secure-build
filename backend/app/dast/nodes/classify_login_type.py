"""NODE 2: classify_login_type - extracts login-page signals and asks the LLM to classify the auth flow."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from langgraph.graph import END

from ..llm_utils import ask_json, print_snippet
from ..screenshot import save_page_screenshot
from ..state import GraphState
from .login import open_login_page

if TYPE_CHECKING:  # lazy: playwright is only needed when a real crawl runs
    from playwright.sync_api import Page

LOGIN_TYPES = {"simple_form", "multi_step", "oauth_sso", "captcha", "otp_2fa", "unknown"}

# simple_form and multi_step both go to the step-by-step login loop (`nodes/login.py`), which
# re-reads the page after every action and so covers a username-then-password flow without a
# special case. oauth_sso, captcha and otp_2fa still stop: they need a third party, a solved
# challenge, or a code from outside the browser. A recorded HAR (`login_har` on the secret)
# is the way through those.
UNSUPPORTED_LOGIN_TYPES = {"oauth_sso", "captcha", "otp_2fa", "unknown"}

# The reply the `fingerprint` model task must return for a login classification. A value outside
# the enum fails validation, gets one repair attempt, and then falls back to "unknown".
LOGIN_CLASSIFICATION_SCHEMA = {
    "type": "object",
    "required": ["login_type"],
    "properties": {
        "login_type": {"type": "string", "enum": sorted(LOGIN_TYPES)},
        "reason": {"type": "string"},
    },
}

KEYWORDS = [
    "sign in with", "google", "microsoft", "github", "sso",
    "captcha", "verification code", "otp", "two-factor", "2fa",
]

EXPLANATIONS = {
    "multi_step": "Login is a multi-step flow (username first, then a separate password step), which is not automated.",
    "oauth_sso": "Login requires OAuth/SSO via a third party, which cannot be automated with username/password alone.",
    "captcha": "Login is protected by a CAPTCHA challenge, which cannot be automated.",
    "otp_2fa": "Login requires a one-time code / two-factor step, which cannot be automated without an external OTP source.",
    "unknown": "Could not confidently classify the login type.",
}


def _looks_like_simple_form(details: dict) -> bool:
    """True when one form already shows a password field plus a username/email field.

    Small models often classify that page as `unknown` because a cookie banner and a
    search box sit above the form in the DOM summary. The fields themselves are enough."""
    for form in details.get("forms") or []:
        inputs = form.get("inputs") or []
        types = {(i.get("type") or "").lower() for i in inputs}
        names = {(i.get("name") or "").lower() for i in inputs}
        ids = {(i.get("id") or "").lower() for i in inputs}
        has_password = "password" in types
        has_user = "email" in types or bool({"email", "username", "user", "login"} & (names | ids))
        if has_password and has_user:
            return True
    return False


def extract_page_details(page: Page) -> dict:
    """Deterministically pull login-relevant signals from the current page (no LLM)."""
    forms = page.eval_on_selector_all(
        "form",
        """
        (forms) => forms.map((form) => ({
            inputs: Array.from(form.querySelectorAll("input")).map((i) => ({
                name: i.name || null,
                type: i.type || null,
                id: i.id || null,
            })),
            buttons: Array.from(form.querySelectorAll("button, input[type='submit']"))
                .map((b) => (b.innerText || b.value || "").trim())
                .filter(Boolean),
        }))
        """,
    )
    iframes = page.eval_on_selector_all(
        "iframe",
        "(frames) => frames.map((f) => ({ src: f.getAttribute('src') }))",
    )
    body_text = ""
    try:
        body_text = page.inner_text("body").lower()
    except Exception:  # noqa: BLE001
        pass
    found_keywords = [kw for kw in KEYWORDS if kw in body_text]

    return {
        "forms": forms,
        "iframes": iframes,
        "found_keywords": found_keywords,
        "current_url": page.url,
    }


def classify_login_type(state: GraphState) -> GraphState:
    verbose = state.get("verbose", True)
    try:
        open_login_page(state["page"], state["login_url"])
    except Exception as exc:  # noqa: BLE001
        state["login_type"] = "unknown"
        state["login_type_reason"] = f"Failed to load login page: {exc}"
        state["stop_reason"] = "unknown"
        print(f"[2/4] FAILED to load login page: {exc}")
        return state

    print("[2/4] Extracting login page details and classifying login type...")
    print(f"    Executing: page.goto('{state['login_url']}')")
    save_page_screenshot(state, state.get("page"), "login.jpg")

    try:
        page_details = extract_page_details(state["page"])
    except Exception as exc:  # noqa: BLE001
        page_details = {"forms": [], "iframes": [], "found_keywords": [], "current_url": state["page"].url}
        print(f"    (extraction warning: {exc})")

    state["page_details"] = page_details
    print_snippet("Extracted page_details sent to LLM", json.dumps(page_details, indent=2), verbose)

    summary = json.dumps(page_details)[:4000]  # keep prompt size reasonable
    prompt = f"""You are analyzing a web login page to classify its authentication flow.

Page signals (forms/inputs/buttons, iframes, matched keywords, current URL):
{summary}

Classify the login into EXACTLY one of these categories:
- simple_form: one page has a username/email field, a password field, and a submit button, all visible at once, no third-party redirect
- multi_step: username/email is entered first, requiring a "Next"-style click before a password field appears
- oauth_sso: page offers "Sign in with Google/Microsoft/GitHub/etc." as the primary or only option, or redirects to a third-party auth domain
- captcha: a CAPTCHA challenge is visibly present on the login form
- otp_2fa: the form or page text indicates a one-time code / two-factor step is required as part of login
- unknown: none of the above clearly apply, or you are not confident

Respond with STRICT JSON only, no extra text, in this exact shape:
{{"login_type": "<one of the categories above>", "reason": "<short justification>"}}
"""

    result = ask_json(state["gateway"], "fingerprint", prompt, LOGIN_CLASSIFICATION_SCHEMA)

    if result is None or result.get("login_type") not in LOGIN_TYPES:
        state["login_type"] = "unknown"
        state["login_type_reason"] = "LLM classification failed"
    else:
        state["login_type"] = result["login_type"]
        state["login_type_reason"] = result.get("reason", "")

    if state["login_type"] == "unknown" and _looks_like_simple_form(page_details):
        state["login_type"] = "simple_form"
        state["login_type_reason"] = "username/email, password and submit are all on this page"
        state["stop_reason"] = ""

    print(f"[2/4] Classification: {state['login_type']} (reason: '{state['login_type_reason']}')")

    if state["login_type"] in UNSUPPORTED_LOGIN_TYPES:
        state["stop_reason"] = f"{state['login_type']}_not_supported"
        print(f"[2/4] Stopping: {EXPLANATIONS.get(state['login_type'], 'Unsupported login type.')} "
              f"Reason: {state['stop_reason']}")

    return state


def route_after_classification(state: GraphState) -> str:
    """Conditional routing: proceed to login for simple_form; stop otherwise."""
    if state["login_type"] in UNSUPPORTED_LOGIN_TYPES:
        return END
    return "login"
