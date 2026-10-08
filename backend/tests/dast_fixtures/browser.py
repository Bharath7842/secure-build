"""A fake browser and site: enough of Playwright's page API for the login, crawl and recorder code
to run offline.

    site = FakeSite(base="http://target.test")
    site.page("/", title="Home", links=["/a", "/b"], xhr=[("GET", "/api/items", 200, "application/json")])
    site.page("/account", requires_login=True, links=["/"])
    site.user("admin", "admin-pw")
    factory = FakeBrowserFactory(site)
    session = factory.new_session(spec)        # an isolated "context" + page

A page that `requires_login` redirects to `/login` unless the session is signed in; `site.expire("label")`
signs a session out behind the crawler's back, which is how session loss is simulated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any
from urllib.parse import urljoin, urlsplit

from app.dast.domain.traffic import record_exchange


@dataclass
class SitePage:
    title: str = ""
    links: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    xhr: list[tuple] = field(default_factory=list)  # (method, path, status, content_type[, request_body])
    requires_login: bool = False
    text: str = ""


class FakeSite:
    def __init__(self, base: str = "http://target.test", login_path: str = "/login") -> None:
        self.base, self.login_path = base, login_path
        self.pages: dict[str, SitePage] = {}
        self.users: dict[str, str] = {}
        self.expired: set[str] = set()
        self.visits: list[tuple[str, str]] = []  # (identity label, path)
        self.on_visit: Any = None  # callable(label, path), run before a visit is served
        self.logins: list[tuple[str, bool]] = []  # (username, accepted)
        self.page(login_path, title="Login", forms=[{"action": login_path, "method": "POST", "inputs": [{"name": "username", "type": "text"}, {"name": "password", "type": "password"}]}])

    def page(self, path: str, **kwargs: Any) -> SitePage:
        self.pages[path] = SitePage(**kwargs)
        return self.pages[path]

    def user(self, username: str, password: str) -> None:
        self.users[username] = password

    def expire(self, label: str) -> None:
        self.expired.add(label)

    def url(self, path: str) -> str:
        return self.base + path


class _Elements:
    def __init__(self, items: list[dict]) -> None:
        self._items = items
        self.first = _Element(items[0]) if items else _Element({})

    def count(self) -> int:
        return len(self._items)

    def nth(self, index: int) -> "_Element":
        return _Element(self._items[index])

    def is_visible(self) -> bool:
        return bool(self._items)

    def click(self, **kwargs: Any) -> None:
        return None


class _Element:
    def __init__(self, data: dict) -> None:
        self._data = data

    def get_attribute(self, name: str) -> str | None:
        return self._data.get(name)

    def inner_text(self) -> str:
        return self._data.get("text", "")

    def is_visible(self) -> bool:
        return True

    def click(self, **kwargs: Any) -> None:
        return None

    def evaluate(self, script: str) -> str:
        return "a"


class FakeContext:
    def __init__(self, session: "FakeBrowserSession") -> None:
        self._session, self._listeners = session, []

    def on(self, event: str, callback: Any) -> None:
        if event == "response":
            self._listeners.append(callback)

    def cookies(self) -> list[dict]:
        if not self._session.signed_in:
            return []
        host = urlsplit(self._session.site.base).hostname or ""
        return [{"name": "session", "value": f"sess-{self._session.spec.label}", "domain": host, "path": "/"}]

    def fire(self, method: str, url: str, status: int, content_type: str, resource_type: str = "xhr") -> None:
        response = SimpleNamespace(
            url=url, status=status, headers={"content-type": content_type},
            request=SimpleNamespace(method=method, resource_type=resource_type, headers={}, post_data=None),
        )
        for callback in self._listeners:
            callback(response)

    def close(self) -> None:
        self._session.closed = True


class FakePage:
    def __init__(self, session: "FakeBrowserSession") -> None:
        self._s = session
        self.url = "about:blank"
        self.context = session.context
        self.keyboard = SimpleNamespace(press=lambda *_: None)
        self.filled: dict[str, str] = {}

    # ---- navigation ----------------------------------------------------------------------------

    @property
    def _path(self) -> str:
        return urlsplit(self.url).path or "/"

    def _current(self) -> SitePage | None:
        return self._s.site.pages.get(self._path)

    def goto(self, url: str, timeout: int | None = None) -> Any:
        site = self._s.site
        self._s.site.visits.append((self._s.spec.label, urlsplit(url).path or "/"))
        if site.on_visit is not None:
            site.on_visit(self._s.spec.label, urlsplit(url).path or "/")
        if self._s.spec.label in site.expired:
            self._s.signed_in = False
            site.expired.discard(self._s.spec.label)
        path = urlsplit(url).path or "/"
        page = site.pages.get(path)
        if page is None:
            self.url = url
            return SimpleNamespace(status=404)
        if page.requires_login and not self._s.signed_in and not self._s.preauth:
            self.url = site.url(site.login_path)
            return SimpleNamespace(status=302)
        self.url = url
        for item in page.xhr:
            method, xpath, status, ctype = item[:4]
            body = item[4] if len(item) > 4 else None
            full = site.url(xpath)
            self.context.fire(method, full, status, ctype)
            if self._s.traffic is not None:
                self._s.traffic.append(
                    record_exchange(method=method, url=full, resource_type="xhr", status=status, request_headers={"content-type": "application/json"} if body else {},
                                    request_body=body, response_headers={"content-type": ctype}, response_body="{}", identity_id=self._s.spec.identity_id)
                )
        return SimpleNamespace(status=200)

    def wait_for_selector(self, *a: Any, **k: Any) -> None:
        return None

    def wait_for_load_state(self, *a: Any, **k: Any) -> None:
        return None

    def wait_for_function(self, *a: Any, **k: Any) -> None:
        return None

    def wait_for_timeout(self, *a: Any) -> None:
        return None

    def screenshot(self, *, path: str | None = None, type: str | None = None, quality: int | None = None) -> bytes:
        self._s.screenshots.append({"path": path, "type": type, "quality": quality})
        data = b"\xff\xd8\xff\xe0fake-jpeg-bytes"
        if path:
            from pathlib import Path

            Path(path).write_bytes(data)
        return data

    # ---- reading -------------------------------------------------------------------------------

    def title(self) -> str:
        page = self._current()
        return page.title if page else ""

    def content(self) -> str:
        return f"<html><title>{self.title()}</title></html>"

    def inner_text(self, selector: str) -> str:
        page = self._current()
        return page.text if page else ""

    def eval_on_selector_all(self, selector: str, script: str) -> list:
        page = self._current()
        if selector == "form" and page:
            return [{"action": f.get("action", ""), "method": f.get("method", "GET"), "inputs": f.get("inputs", []), "buttons": ["Sign in"]} for f in page.forms]
        return []

    def locator(self, selector: str) -> _Elements:
        page = self._current()
        on_login = self._path == self._s.site.login_path
        if selector == 'input[type="password"]':
            return _Elements([{}] if on_login else [])
        if selector == "a[href]":
            return _Elements([{"href": link, "text": link} for link in (page.links if page else [])])
        if "logout" in selector.lower() or "log out" in selector.lower() or "sign out" in selector.lower():
            return _Elements([{}] if self._s.signed_in and not on_login else [])
        if selector in ('input[name="username"]', 'button[type="submit"]'):
            return _Elements([{}] if on_login else [])
        return _Elements([])

    # ---- actions -------------------------------------------------------------------------------

    def fill(self, selector: str, value: str, timeout: int | None = None) -> None:
        self.filled[selector] = value

    def click(self, selector: str, timeout: int | None = None, force: bool = False) -> None:
        site = self._s.site
        if self._path != site.login_path:
            return
        username = next((v for k, v in self.filled.items() if "user" in k.lower() or "email" in k.lower()), "")
        password = next((v for k, v in self.filled.items() if "pass" in k.lower() or "p" == k.strip("#")), "")
        accepted = site.users.get(username) == password and bool(password)
        site.logins.append((username, accepted))
        if accepted:
            self._s.signed_in = True
            self.url = site.url("/home" if "/home" in site.pages else "/")


class FakeBrowserSession:
    def __init__(self, site: FakeSite, spec: Any, traffic: list | None, preauth: bool = False) -> None:
        self.site, self.spec, self.traffic, self.preauth = site, spec, traffic, preauth
        self.signed_in = preauth
        self.closed = False
        self.screenshots: list[dict] = []
        self.context = FakeContext(self)
        self.page = FakePage(self)

    def cookies(self) -> list[dict]:
        return self.context.cookies()

    def close(self) -> None:
        self.closed = True


class FakeBrowserFactory:
    """Implements `app.dast.runtime.BrowserFactory`. `sessions` lists every context it created."""

    def __init__(self, site: FakeSite, traffic: list | None = None) -> None:
        self.site, self.traffic = site, traffic if traffic is not None else []
        self.sessions: list[FakeBrowserSession] = []
        self.requested: list[dict] = []
        self.closed = False

    @property
    def started(self) -> bool:
        return bool(self.sessions)

    def new_session(self, spec: Any, *, storage_state: dict | None = None, extra_headers: dict | None = None) -> FakeBrowserSession:
        self.requested.append({"label": spec.label, "storage_state": storage_state, "extra_headers": extra_headers})
        session = FakeBrowserSession(self.site, spec, self.traffic, preauth=bool(storage_state) or bool(extra_headers))
        self.sessions.append(session)
        return session

    def close(self) -> None:
        self.closed = True


class ScriptedProbeDriver:
    """A ProbeDriver whose answers are scripted. Used by the browser-probe tests; no Playwright."""

    def __init__(self, fields=None, *, execute_when=None, sinks_when=None, echo_when=None, live_when=None) -> None:
        self._fields = fields or {}
        self.execute_when = execute_when or (lambda url, payload: False)
        self.sinks_when = sinks_when or (lambda url, payload: ())
        self.echo_when = echo_when or (lambda url, payload: False)
        self.live_when = live_when or (lambda payload: False)
        self.token = ""
        self.current = ""
        self.opened: list[str] = []
        self.submitted: list[tuple[Any, str]] = []

    def install(self, token: str) -> None:
        self.token = token

    def open(self, url: str, watch) -> Any:
        from app.dast.browser_probe import ProbeHit

        self.current = url
        self.opened.append(url)
        payload = watch[-1] if watch else ""
        return ProbeHit(
            url=url, status=200,
            executed=bool(self.execute_when(url, payload)),
            sinks=tuple(self.sinks_when(url, payload)),
            echoed=bool(self.echo_when(url, payload)),
        )

    def fields(self) -> list:
        for key, items in self._fields.items():
            if key in self.current:
                return list(items)
        return []

    def submit(self, field, payload: str):
        from app.dast.browser_probe import ProbeHit

        self.submitted.append((field, payload))
        where = f"submit:{field.name}"
        return ProbeHit(
            url=self.current, status=200,
            executed=bool(self.execute_when(where, payload)),
            sinks=tuple(self.sinks_when(where, payload)),
        )

    def live_markup(self, payload: str) -> bool:
        return bool(self.live_when(payload))
