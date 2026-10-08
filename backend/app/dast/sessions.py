"""Per-identity sessions (DAST-06-020): the one place that knows which credentials belong to
which identity.

Isolation is the point. A session carries only its own identity's token header and cookies, and
`request_headers` is the only way engine code builds headers for a request made *as* an identity,
so a request made as User cannot carry Admin's cookie. Browser state is isolated the same way: each
session owns a separate browser context (see `runtime.BrowserFactory`). The audit row of every
request names the identity label, which is how tests (and an operator) check this.

No secret is stored here beyond what a request needs to be sent: tokens and cookies live in
memory in `IdentitySession` for the scan, and the credential holder registers them for redaction.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Mapping

from .domain.auth import cookie_header, token_header
from .domain.entities import RoleName
from .domain.identities import AuthMethod, IdentitySpec
from .domain.interfaces import GuardDecision, RequestSpec

PENDING, AUTHENTICATED, FAILED, ANONYMOUS = "pending", "authenticated", "failed", "anonymous"


@dataclass
class IdentitySession:
    spec: IdentitySpec
    status: str = PENDING
    failure: str = ""
    token_header: tuple[str, str] | None = None  # (header name, header value)
    cookies: list[dict] = field(default_factory=list)  # Playwright-style cookie dicts
    storage_state: dict | None = None
    browser_session: Any = None  # a runtime.BrowserSession, created on demand
    relogin_count: int = 0
    csrf_header: str = ""
    csrf_token: str = ""
    login_url: str = ""
    start_url: str = ""  # where this identity's crawl begins (the page it landed on after login)

    @property
    def label(self) -> str:
        return self.spec.label

    def public(self) -> dict[str, Any]:
        """Non-secret view for the discovery summary."""
        return {
            "identity_id": self.spec.identity_id,
            "label": self.spec.label,
            "role": self.spec.role.name.value,
            "role_label": self.spec.role.label,
            "auth_method": self.spec.auth_method.value,
            "status": self.status,
            "failure": self.failure,
            "relogin_count": self.relogin_count,
        }


class SessionStore:
    def __init__(self, identities: list[IdentitySpec]) -> None:
        self._sessions: dict[str, IdentitySession] = {}
        for spec in identities:
            session = IdentitySession(spec)
            if spec.role.name is RoleName.ANONYMOUS:
                session.status = ANONYMOUS
            self._sessions[spec.identity_id] = session

    def get(self, identity_id: str) -> IdentitySession:
        return self._sessions[identity_id]

    def all(self) -> list[IdentitySession]:
        return list(self._sessions.values())

    def authenticated(self) -> list[IdentitySession]:
        return [s for s in self._sessions.values() if s.status == AUTHENTICATED]

    def usable(self) -> list[IdentitySession]:
        """Sessions that can make requests: authenticated ones, then the anonymous baseline."""
        return self.authenticated() + [s for s in self._sessions.values() if s.status == ANONYMOUS]

    # ---- state changes ------------------------------------------------------------------------

    def set_token(self, identity_id: str, header_name: str, scheme: str, token: str) -> None:
        session = self.get(identity_id)
        session.token_header = token_header(header_name, scheme, token)

    def set_storage_state(self, identity_id: str, raw: str | Mapping[str, Any]) -> None:
        state = json.loads(raw) if isinstance(raw, str) else dict(raw)
        session = self.get(identity_id)
        session.storage_state = state
        session.cookies = list(state.get("cookies") or [])

    def update_cookies(self, identity_id: str, cookies: list[dict]) -> None:
        self.get(identity_id).cookies = list(cookies)

    def note_document(self, identity_id: str, html: str) -> None:
        """Remember a CSRF token seen in a page so later requests from this identity send it back."""
        from .domain.session import csrf_from_html

        found = csrf_from_html(html or "")
        if found is None:
            return
        session = self.get(identity_id)
        session.csrf_header, session.csrf_token = found

    def mark_authenticated(self, identity_id: str) -> None:
        session = self.get(identity_id)
        session.status, session.failure = AUTHENTICATED, ""

    def mark_failed(self, identity_id: str, reason: str) -> None:
        session = self.get(identity_id)
        session.status, session.failure = FAILED, reason

    # ---- requests as an identity --------------------------------------------------------------

    def request_headers(self, identity_id: str, url: str, extra: Mapping[str, str] | None = None) -> dict[str, str]:
        """Headers for a request made as `identity_id`: its own token and cookies, nothing of any
        other identity. An Anonymous (or not yet authenticated) identity sends no credentials."""
        session = self.get(identity_id)
        headers: dict[str, str] = dict(extra or {})
        if session.status == AUTHENTICATED:
            if session.token_header:
                headers[session.token_header[0]] = session.token_header[1]
            cookie = cookie_header(session.cookies, url)
            if cookie:
                headers["Cookie"] = cookie
        if session.csrf_token and session.csrf_header and session.csrf_header not in headers:
            headers[session.csrf_header] = session.csrf_token
        return headers

    def spec_for(
        self,
        identity_id: str,
        method: str,
        url: str,
        *,
        body: Any = None,
        headers: Mapping[str, str] | None = None,
        check_id: str | None = None,
        intent: str | None = None,
        max_body_bytes: int | None = None,
    ) -> RequestSpec:
        session = self.get(identity_id)
        return RequestSpec(
            method=method,
            url=url,
            identity_id=identity_id,
            identity_label=session.label,
            headers=self.request_headers(identity_id, url, headers),
            body=body,
            check_id=check_id,
            intent=intent,
            max_body_bytes=max_body_bytes,
        )

    def send(self, executor: Any, identity_id: str, method: str, url: str, **kwargs: Any) -> GuardDecision:
        return executor.execute(self.spec_for(identity_id, method, url, **kwargs))


def anonymous_id(store: SessionStore) -> str | None:
    return next((s.spec.identity_id for s in store.all() if s.spec.role.name is RoleName.ANONYMOUS), None)


def needs_browser_login(spec: IdentitySpec) -> bool:
    return spec.auth_method is AuthMethod.FORM
