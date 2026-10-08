"""NODE 3: authenticate (DAST-06-020, -030, -040, -050): establish one isolated session per
authenticated identity, by form login, bearer token or a saved browser session.

* **token**: the token header is attached to every request that identity makes; a probe request
  confirms the target accepts it.
* **preauth**: the saved session's cookies seed the identity's requests (and, later, its browser
  context); a probe confirms the target still honours it.
* **form**: the identity gets its own guarded browser context, then the existing classify-and-login
  nodes run against it with a bounded retry. A simple form and a multi-step form both use that
  loop. SSO, CAPTCHA and one-time-code logins stop unless the secret includes a recorded HAR
  (`login_har`), which is replayed through the guarded executor first.

Failure semantics: if any identity cannot authenticate, the scan fails *naming that identity and
the reason* instead of continuing with fewer identities. If its credentials are no longer held
(the process restarted), the scan fails as "credentials lost". The same node re-establishes a
single identity whose session was lost mid-scan (`state["relogin_requested"]`), at most once each.
"""

from __future__ import annotations

import json
import time

from ..domain.entities import Location
from ..domain.har import cookie_from_set_cookie, parse_har
from ..domain.identities import AuthMethod, IdentitySpec
from ..domain.session import (
    SessionVerdict, excessive_cookie_lifetimes, fixation_cookie_names, probe_verdict,
    reused_session_cookies, unsupported_login_message,
)
from ..sessions import AUTHENTICATED, PENDING, SessionStore
from ..stage_findings import enabled_checks, one_row, publish
from ..state import GraphState
from . import classify_login_type as classify
from . import login as login_node

MAX_LOGIN_ATTEMPTS = 2  # the first attempt and one retry


def _probe(state: GraphState, spec: IdentitySpec, kind: str) -> SessionVerdict:
    runtime, store = state["runtime"], state["sessions"]
    decision = store.send(runtime.executor, spec.identity_id, "GET", state["url"])
    response = decision.response
    location = next((v for k, v in (getattr(response, "headers", None) or {}).items() if str(k).lower() == "location"), "")
    error = decision.error or (f"the request was not permitted ({decision.deny_reason})" if decision.deny_reason else "")
    return probe_verdict(response.status if response is not None else None, location=location, error=error, kind=kind)


def _login_state(base: GraphState, page, login_url: str, username: str, password: str) -> dict:
    """The state the classify/login nodes read and write, scoped to one identity."""
    return {
        "gateway": base["gateway"], "page": page, "browser": None, "verbose": base.get("verbose", True),
        "login_url": login_url, "username": username, "password": password,
        "page_details": {}, "login_type": "", "login_type_reason": "", "stop_reason": "",
        "identified_username_selector": "", "identified_password_selector": "", "identified_submit_selector": "",
        "identified_success_indicator": "", "selector_source": "", "login_success": False, "login_error": "",
        "crawl_start_url": base["url"],
        "runtime": base.get("runtime"),
    }


def _form_login(state: GraphState, spec: IdentitySpec, secret: dict) -> tuple[bool, str]:
    runtime, store = state["runtime"], state["sessions"]
    if runtime.browser is None:
        return False, "form login needs a browser, but none is available for this scan"
    session = store.get(spec.identity_id)
    if session.browser_session is not None:  # a re-login starts from a clean context
        try:
            session.browser_session.close()
        except Exception:  # noqa: BLE001
            pass
        session.browser_session = None
    browser_session = runtime.browser.new_session(spec)
    reason = "login did not reach a verified signed-in state"
    with runtime.login_window():  # the login submit is a POST; safe mode would otherwise abort it
        return _login_attempts(state, spec, secret, session, browser_session, reason)


def _login_attempts(state: GraphState, spec: IdentitySpec, secret: dict, session, browser_session, reason: str) -> tuple[bool, str]:
    runtime, store = state["runtime"], state["sessions"]
    for attempt in range(1, MAX_LOGIN_ATTEMPTS + 1):
        sub = _login_state(state, browser_session.page, secret.get("login_url", ""), secret.get("username", ""), secret.get("password", ""))
        print("### DAST: classifying login")
        try:
            before_cookies = list(browser_session.cookies())
        except Exception:  # noqa: BLE001
            before_cookies = []
        sub = classify.classify_login_type(sub)
        if sub.get("login_type") in classify.UNSUPPORTED_LOGIN_TYPES:
            browser_session.close()
            return False, unsupported_login_message(sub["login_type"], spec.label)
        sub = login_node.login(sub)
        if sub.get("login_success"):
            session.browser_session = browser_session
            session.login_url = secret.get("login_url", "")
            session.start_url = sub.get("crawl_start_url") or state["url"]
            after_cookies = list(browser_session.cookies())
            store.update_cookies(spec.identity_id, after_cookies)
            _write_login_cookie_findings(state, spec.label, before_cookies, after_cookies)
            return True, ""
        reason = sub.get("login_error") or reason
        if attempt < MAX_LOGIN_ATTEMPTS:
            print(f"    Login for {spec.label!r} did not succeed ({reason}); retrying once.")
    browser_session.close()
    return False, f"login failed after {MAX_LOGIN_ATTEMPTS} attempts ({reason})"


def authenticate_identity(state: GraphState, spec: IdentitySpec, secret: dict) -> tuple[bool, str]:
    store: SessionStore = state["sessions"]
    method = spec.auth_method
    if method is AuthMethod.TOKEN:
        try:
            store.set_token(spec.identity_id, secret.get("header_name", ""), secret.get("scheme", "Bearer"), secret.get("token", ""))
        except ValueError as exc:
            return False, str(exc)
        store.mark_authenticated(spec.identity_id)
        verdict = _probe(state, spec, "token")
    elif method is AuthMethod.PREAUTH:
        try:
            store.set_storage_state(spec.identity_id, secret.get("storage_state", ""))
        except (ValueError, TypeError):
            return False, "the saved session could not be read"
        store.mark_authenticated(spec.identity_id)
        verdict = _probe(state, spec, "session")
    elif method is AuthMethod.FORM:
        if secret.get("login_har"):
            ok, reason = _replay_har(state, spec, secret.get("login_har"))
            if ok:
                return True, ""
            print(f"    Recorded login for {spec.label!r} did not establish a session ({reason}); trying the form.")
        return _form_login(state, spec, secret)
    else:
        return True, ""
    return (verdict.ok, verdict.reason)


def authenticate(state: GraphState) -> GraphState:
    runtime, store = state["runtime"], state["sessions"]
    relogin = list(state.get("relogin_requested") or [])
    state["relogin_requested"] = []
    wanted = [s for s in runtime.identities if s.authenticated and (s.identity_id in relogin if relogin else store.get(s.identity_id).status == PENDING)]
    if not wanted:
        print("[3/4] No identity needs authentication; continuing as the Anonymous baseline." if not relogin else "[3/4] Nothing to re-establish.")
        return state
    print(f"[3/4] Authenticating {len(wanted)} identit{'y' if len(wanted) == 1 else 'ies'}{' (re-login after a lost session)' if relogin else ''}...")

    for spec in wanted:
        if runtime.cancelled():
            state["stop_reason"] = "cancelled"
            return state
        secret = runtime.credentials.read(spec.identity_id) if runtime.credentials is not None else None
        if secret is None:
            message = (
                f"the credentials for identity {spec.label!r} are no longer available "
                "(the server restarted or the scan lost them); start the scan again"
            )
            store.mark_failed(spec.identity_id, "credentials lost")
            state.update(credentials_lost=True, credentials_lost_reason=message, authentication_failed=message, stop_reason="credentials_lost")
            print(f"[3/4] FAILED: {message}")
            return state
        ok, reason = authenticate_identity(state, spec, dict(secret))
        if not ok:
            store.mark_failed(spec.identity_id, reason)
            message = f"Identity {spec.label!r} could not authenticate: {reason}"
            state.update(authentication_failed=message, stop_reason="authentication_failed")
            print(f"[3/4] FAILED: {message}")
            return state
        store.mark_authenticated(spec.identity_id)
        print(f"[3/4] Identity {spec.label!r} ({spec.role_display}) authenticated by {spec.auth_method.value}.")
    _write_reuse_findings(state)
    state["identity_results"] = [s.public() for s in store.all()]
    return state


def _replay_har(state: GraphState, spec: IdentitySpec, raw) -> tuple[bool, str]:
    """Replay a recorded login against this target and keep the cookies it set."""
    runtime, store = state["runtime"], state["sessions"]
    entries = parse_har(raw, target_url=state["url"])
    if not entries:
        return False, "the recording had no requests to this target"
    cookies: list[dict] = []
    for entry in entries:
        if runtime.cancelled():
            return False, "cancelled"
        decision = store.send(
            runtime.executor, spec.identity_id, entry.method, entry.url,
            headers=dict(entry.headers), body=entry.body, check_id="login-har",
        )
        response = decision.response
        if response is None:
            continue
        for key, value in (response.headers or {}).items():
            if str(key).lower() != "set-cookie":
                continue
            cookie = cookie_from_set_cookie(str(value))
            if cookie:
                cookies.append(cookie)
    if not cookies:
        return False, "the recording set no cookies"
    store.update_cookies(spec.identity_id, cookies)
    store.mark_authenticated(spec.identity_id)
    verdict = _probe(state, spec, "session")
    if not verdict.ok:
        store.get(spec.identity_id).status = PENDING
        return False, verdict.reason or "the recorded session was not accepted"
    print(f"    Recorded login for {spec.label!r} established a session ({len(entries)} request(s)).")
    return True, ""


def _write_login_cookie_findings(state: GraphState, label: str, before: list, after: list) -> None:
    runtime = state.get("runtime")
    checks = enabled_checks(getattr(runtime, "rule_set", None), ("dast-session-fixation", "dast-session-timeout"), getattr(runtime, "skipped_degraded", ()) or ())
    rows = []
    if "dast-session-fixation" in checks:
        names = fixation_cookie_names(before, after)
        if names:
            rows.append(
                one_row(
                    checks["dast-session-fixation"], signal="session_fixed",
                    detail=f"cookie {', '.join(names)} kept the same value across login",
                    target=label, title=f"Session fixation: {label}", source="authenticate", sink=state.get("url") or "",
                    location=Location.HEADER,
                )
            )
    if "dast-session-timeout" in checks:
        for name, lifetime in excessive_cookie_lifetimes(after, now_s=time.time()):
            rows.append(
                one_row(
                    checks["dast-session-timeout"], signal="session_lifetime_excessive",
                    detail=f"cookie {name} stays valid for {lifetime // 3600} hour(s)",
                    target=label, title=f"Excessive session lifetime: {name}", source="authenticate", sink=state.get("url") or "",
                    location=Location.HEADER,
                )
            )
    publish(state, runtime, "session", rows)


def _write_reuse_findings(state: GraphState) -> None:
    runtime, store = state.get("runtime"), state["sessions"]
    checks = enabled_checks(getattr(runtime, "rule_set", None), ("dast-credential-reuse",), getattr(runtime, "skipped_degraded", ()) or ())
    if "dast-credential-reuse" not in checks:
        return
    by_label = {session.label: session.cookies for session in store.authenticated()}
    rows = []
    for name, left, right in reused_session_cookies(by_label):
        rows.append(
            one_row(
                checks["dast-credential-reuse"], signal="credential_reused",
                detail=f"{left} and {right} share session cookie {name}",
                target=f"{left} / {right}", title=f"Session cookie reused: {name}", source="authenticate",
                sink=state.get("url") or "", location=Location.HEADER,
            )
        )
    publish(state, runtime, "session", rows)


def route_after_authenticate(state: GraphState) -> str:
    return "end" if state.get("authentication_failed") or state.get("stop_reason") == "cancelled" else "discover"
