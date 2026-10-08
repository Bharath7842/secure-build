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
