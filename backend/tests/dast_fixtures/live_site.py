"""A small real web site on a local port, for `live` tests that drive a real browser.

    with LiveSite() as site:
        site.base       # "http://127.0.0.1:<port>"
        site.requests   # every request the server saw: (method, path, headers dict)

Routes: `/` (links), `/login` (a form; POST sets a `session` cookie and redirects to `/home`),
`/home` and `/account` (need the cookie; `/home` has localized controls and `/account` makes an
XHR POST with a password field in its body), `/api/me` (JSON, needs the cookie, else 401),
`/api/auth/logout` (clears the session), `/static/app.js`, `/openapi.json`, and `/delete-all`
(a state-changing GET-looking link the crawler must not follow).
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

USER, PASSWORD = "alice", "alice-live-pw"
SESSION = "live-session-abc123"

PAGES = {
    "/": '<html><head><title>Public home</title></head><body><h1>Shop</h1><a href="/login">Login</a> <a href="/about">About</a> <a href="http://other.invalid/x">elsewhere</a></body></html>',
    "/about": "<html><head><title>About</title></head><body><p>about us</p><a href='/'>home</a></body></html>",
    "/login": (
        "<html><head><title>Login</title></head><body><form method='POST' action='/login'>"
        "<input id='u' name='username' type='text'><input id='p' name='password' type='password'>"
        "<button id='go' type='submit'>Sign in</button></form></body></html>"
    ),
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
    "/account": (
        "<html><head><title>Account</title><script src='/static/app.js'></script></head><body><a href='/home'>Home</a> <a href='/logout'>Log out</a>"
        "<script>fetch('/api/me').then(r=>r.json());"
        "fetch('/api/me', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({email:'a@x.test', password:'p-in-body'})});</script></body></html>"
    ),
}
OPENAPI = {"openapi": "3.0.0", "paths": {"/api/me": {"get": {}, "post": {}}, "/api/orders": {"get": {}}}}


class _Handler(BaseHTTPRequestHandler):
    server: "ThreadingHTTPServer"

    def log_message(self, *args):  # silence
        return

    def _cookie_ok(self) -> bool:
        return f"session={SESSION}" in (self.headers.get("Cookie") or "")

    def _send(self, status: int, body: str, ctype: str = "text/html; charset=utf-8", headers: dict | None = None) -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _record(self) -> None:
        self.server.requests.append((self.command, self.path, dict(self.headers)))  # type: ignore[attr-defined]

    def do_GET(self) -> None:  # noqa: N802
        self._record()
        path = self.path.split("?")[0]
        if path in ("/home", "/account") and not self._cookie_ok():
            return self._send(302, "", headers={"Location": "/login"})
        if path == "/" and self._cookie_ok():  # signed-in visitors see links to the protected area
            return self._send(200, PAGES["/"].replace("<h1>Shop</h1>", "<h1>Shop</h1><a href='/home'>Dashboard</a> <a href='/account'>Account</a>"))
        if path in PAGES:
            return self._send(200, PAGES[path])
        if path == "/static/app.js":
            return self._send(200, "console.log('app')", "application/javascript")
        if path == "/openapi.json":
            return self._send(200, json.dumps(OPENAPI), "application/json")
        if path == "/api/me":
            return self._send(200, '{"email":"a@x.test"}', "application/json") if self._cookie_ok() else self._send(401, '{"error":"auth"}', "application/json")
        if path == "/logout":
            return self._send(200, "<p>bye</p>")
        self._send(404, "not found", "text/plain")

    def do_POST(self) -> None:  # noqa: N802
        self._record()
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode() if length else ""
        path = self.path.split("?")[0]
        if path == "/login":
            fields = dict(p.split("=", 1) for p in body.split("&") if "=" in p)
            if fields.get("username") == USER and fields.get("password") == PASSWORD:
                return self._send(302, "", headers={"Location": "/home", "Set-Cookie": f"session={SESSION}; Path=/; HttpOnly"})
            return self._send(200, PAGES["/login"] + "<p>bad credentials</p>")
        if path == "/api/auth/logout":
            return self._send(
                204,
                "",
                headers={"Set-Cookie": "session=; Path=/; Max-Age=0; HttpOnly"},
            )
        if path == "/api/me":
            return self._send(200, '{"ok":true}', "application/json") if self._cookie_ok() else self._send(401, '{"error":"auth"}', "application/json")
        self._send(404, "not found", "text/plain")


class LiveSite:
    def __init__(self) -> None:
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._server.requests = []  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    @property
    def requests(self) -> list:
        return self._server.requests  # type: ignore[attr-defined]

    def paths(self, method: str | None = None) -> list[str]:
        return [p.split("?")[0] for m, p, _ in self.requests if method is None or m == method]

    def __enter__(self) -> "LiveSite":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()
