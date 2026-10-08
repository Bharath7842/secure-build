"""An in-process fake web target built on httpx's mock transport.

No sockets are opened, so it works with anything that sends requests through an
`httpx.Client` (including the guarded request executor): hand `target.transport`
or `target.client()` to the code under test and inspect `target.requests`.

    target = FakeTarget()
    target.add_page("/", "<h1>Home</h1>", headers={"X-Frame-Options": "DENY"})
    target.protect("/api/admin/users", roles=["admin"])
    client = target.client()
    client.post("/login", json={"username": "admin", "password": "admin-pw"})
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

import httpx

Handler = Callable[[httpx.Request], httpx.Response]

DEFAULT_BASE_URL = "http://target.test"

# Pages the browser-probe tests and the hostile target share. The DOM page writes the query
# string into innerHTML. The SPA search box has no form. The comment form stores a POST body
# and renders it back unescaped on the next GET.
DOM_SINK_PAGE = """<!doctype html><html><body>
<script>var q = new URLSearchParams(location.search).get("q") || ""; if (q) document.body.innerHTML = q;</script>
</body></html>"""
SPA_SEARCH_PAGE = """<!doctype html><html><body>
<input type="search" id="search" aria-label="search">
<div id="out"></div>
<script>
document.getElementById("search").addEventListener("change", function () {
  document.getElementById("out").innerHTML = this.value;
});
</script>
</body></html>"""
COMMENT_FORM_PAGE = """<!doctype html><html><body>
<form method="POST" action="/comments"><textarea name="comment"></textarea>
<input type="hidden" name="csrf" value="tok"><button type="submit">Post</button></form>
<div id="stored"></div>
</body></html>"""
CLEAN_PAGE = """<!doctype html><html><body><h1>Clean</h1><input name="note" type="text"></body></html>"""


@dataclass
class FakeUser:
    username: str
    password: str
    role: str
    token: str


@dataclass
class _Route:
    handler: Handler


@dataclass
class FakeTarget:
    base_url: str = DEFAULT_BASE_URL
    requests: list[httpx.Request] = field(init=False, default_factory=list)
    users: dict[str, FakeUser] = field(init=False, default_factory=dict)
    _routes: dict[tuple[str, str], _Route] = field(init=False, default_factory=dict)
    _sessions: dict[str, FakeUser] = field(init=False, default_factory=dict)

    def __post_init__(self) -> None:
        # Two users, enough for role-pair (authorization) tests.
        self.add_user("admin", "admin-pw", role="admin")
        self.add_user("user", "user-pw", role="user")
        self.route("POST", "/login", self._login)

    # ---- configuration -------------------------------------------------------------------

    def add_user(self, username: str, password: str, *, role: str) -> FakeUser:
        user = FakeUser(username, password, role, token=f"tok-{username}")
        self.users[username] = user
        self._sessions[user.token] = user
        return user

    def route(self, method: str, path: str, handler: Handler) -> None:
        self._routes[(method.upper(), path)] = _Route(handler)

    def add_browser_xss_pages(self) -> None:
        """DOM sink, a form-less search box, a stored-comment form, and a clean control page."""
        stored: list[str] = []
        self.add_page("/dom", DOM_SINK_PAGE)
        self.add_page("/spa", SPA_SEARCH_PAGE)
        self.add_page("/clean", CLEAN_PAGE)

        def show(request: httpx.Request) -> httpx.Response:
            body = COMMENT_FORM_PAGE.replace('<div id="stored"></div>', "".join(f"<div>{item}</div>" for item in stored))
            return httpx.Response(200, text=body, headers={"content-type": "text/html"})

        def save(request: httpx.Request) -> httpx.Response:
            stored.append(request.content.decode("utf-8", "replace"))
            return httpx.Response(200, text="<p>saved</p>", headers={"content-type": "text/html"})

        self.route("GET", "/comments", show)
        self.route("POST", "/comments", save)

    def add_page(
        self,
        path: str,
        html: str = "",
        *,
        status: int = 200,
        headers: Mapping[str, str] | None = None,
        cookies: Mapping[str, str] | None = None,
        method: str = "GET",
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            # A header list (not a dict) so several Set-Cookie headers can coexist.
            header_list = [("content-type", "text/html"), *(headers or {}).items()]
            header_list += [("set-cookie", f"{name}={value}; Path=/") for name, value in (cookies or {}).items()]
            return httpx.Response(status, text=html, headers=header_list)

        self.route(method, path, handler)

    def add_json(
        self,
        path: str,
        data: Any,
        *,
        method: str = "GET",
        status: int = 200,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.route(
            method,
            path,
            lambda request: httpx.Response(status, json=data, headers=dict(headers or {})),
        )

    def set_openapi(self, document: Mapping[str, Any], path: str = "/openapi.json") -> None:
        self.add_json(path, document)

    def protect(self, path: str, *, roles: Sequence[str], method: str = "GET", body: Any = None) -> None:
        """401 for anonymous callers, 403 for a logged-in user whose role is not allowed, else 200."""

        def handler(request: httpx.Request) -> httpx.Response:
            user = self.user_for(request)
            if user is None:
                return httpx.Response(401, json={"error": "authentication required"})
            if user.role not in roles:
                return httpx.Response(403, json={"error": "forbidden"})
            return httpx.Response(200, json=body if body is not None else {"path": path, "as": user.username})

        self.route(method, path, handler)

    # ---- the transport -------------------------------------------------------------------

    def user_for(self, request: httpx.Request) -> FakeUser | None:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            return self._sessions.get(auth[7:].strip())
        for part in request.headers.get("cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == "session":
                return self._sessions.get(value)
        return None

    def _login(self, request: httpx.Request) -> httpx.Response:
        try:
            body = json.loads(request.content or b"{}")
        except ValueError:
            return httpx.Response(400, json={"error": "malformed body"})
        user = self.users.get(body.get("username", ""))
        if user is None or user.password != body.get("password"):
            return httpx.Response(401, json={"error": "invalid credentials"})
        return httpx.Response(
            200,
            json={"token": user.token, "role": user.role},
            headers=[("set-cookie", f"session={user.token}; Path=/; HttpOnly")],
        )

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        route = self._routes.get((request.method.upper(), request.url.path))
        if route is None:
            return httpx.Response(404, text="not found", headers={"content-type": "text/plain"})
        return route.handler(request)

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def client(self, **kwargs: Any) -> httpx.Client:
        kwargs.setdefault("base_url", self.base_url)
        return httpx.Client(transport=self.transport, **kwargs)

    def async_client(self, **kwargs: Any) -> httpx.AsyncClient:
        kwargs.setdefault("base_url", self.base_url)
        return httpx.AsyncClient(transport=self.transport, **kwargs)

    # ---- inspection ----------------------------------------------------------------------

    def requests_to(self, path: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.path == path]
