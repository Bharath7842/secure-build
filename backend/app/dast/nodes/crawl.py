"""NODE 4: crawl - discovers same-domain pages, forms, and API endpoints via an LLM-directed loop."""

from __future__ import annotations

import json
import re
import time
from typing import TYPE_CHECKING, Optional
from urllib.parse import urljoin

from ..llm_utils import ask_json
from ..screenshot import save_page_screenshot
from .login import looks_logged_in
from ..state import GraphState
from ..url_utils import get_url_pattern, is_same_domain, normalize_url

if TYPE_CHECKING:  # lazy: playwright is only needed when a real crawl runs
    from playwright.sync_api import BrowserContext, Page

# Guards against destructive anchors being queued and navigated. This is a
# conservative filter, not a complete classifier for every language or target.
DESTRUCTIVE_PATTERNS = re.compile(
    r"(?i)(log[\s\-_]?out|sign[\s\-_]?out|delete|deactivate|remove|reset|invalidate|\bdrop\b)"
)


def is_safe_to_visit(url: str, link_text: str = "") -> bool:
    return not (DESTRUCTIVE_PATTERNS.search(url or "") or DESTRUCTIVE_PATTERNS.search(link_text or ""))


STOP_REASONS = [
    "queue_empty", "max_pages_reached", "max_depth_reached",
    "max_runtime_reached", "diminishing_returns", "other",
]

# The reply the `crawl_plan` model task returns: either pick the next queued URL or stop. `url`
# must match one in the queue exactly (checked below; a made-up one falls back to FIFO).
CRAWL_PLAN_SCHEMA = {
    "type": "object",
    "required": ["action"],
    "properties": {
        "action": {"type": "string", "enum": ["choose_next_url", "stop_crawl"]},
        "url": {"type": "string"},
        "reason": {"type": "string", "maxLength": 200},
        "stop_reason": {"type": "string", "enum": STOP_REASONS},
        "details": {"type": "string"},
    },
}


def setup_network_capture(context: BrowserContext, state: GraphState) -> None:
    """Attach a response listener that logs API-looking calls into state.api_calls."""
    seen_keys = set()

    def on_response(response) -> None:
        try:
            request = response.request
            method = request.method
            url = response.url
            status = response.status
            content_type = response.headers.get("content-type", "")
            resource_type = request.resource_type
            is_api = (
                "application/json" in content_type
                or resource_type in ("xhr", "fetch")
                or "/api/" in url
                or "/graphql" in url
            )
            if not is_api:
                return
            key = (method, url)
            if key in seen_keys:
                return
            seen_keys.add(key)
            state["api_calls"].append({
                "method": method,
                "url": url,
                "status_code": status,
                "content_type": content_type,
            })
        except Exception:  # noqa: BLE001
            pass  # network capture is best-effort; never let it break the crawl

    context.on("response", on_response)


def _extract_hrefs(page: Page, base_url: str, same_domain_mode: str) -> list:
    """Collect same-domain, non-destructive <a href> targets.

    Uses Playwright locators rather than a raw in-page querySelectorAll: Playwright's
    selector engine pierces open shadow roots automatically, so links rendered inside
    web components (common in Angular Material / modern component libraries) are still
    found, where a plain document.querySelectorAll would miss them.
    """
    links = []
    try:
        anchors = page.locator("a[href]")
        count = min(anchors.count(), 200)  # cap: avoid pathological per-element round trips
        for i in range(count):
            try:
                el = anchors.nth(i)
                raw_href = el.get_attribute("href")
                # get_attribute() returns the raw attribute (often relative, e.g. "/settings"),
                # unlike the DOM's .href property which the browser resolves automatically.
                href = urljoin(page.url, raw_href) if raw_href else None
                text = (el.inner_text() or "").strip()[:80]
            except Exception:  # noqa: BLE001
                continue
            if not href or not is_same_domain(href, base_url, same_domain_mode):
                continue
            if not is_safe_to_visit(href, text):
                continue
            links.append(href)
    except Exception:  # noqa: BLE001
        pass
    return links


def extract_links_and_forms(page: Page, base_url: str, same_domain_mode: str):
    same_domain_links = _extract_hrefs(page, base_url, same_domain_mode)

    try:
        forms = page.eval_on_selector_all(
            "form",
            """
            (forms) => forms.map((f) => ({
                action: f.getAttribute('action') || '',
                method: (f.getAttribute('method') || 'GET').toUpperCase(),
                inputs: Array.from(f.querySelectorAll('input, select, textarea')).map((i) => ({
                    name: i.name || null,
                    type: i.type || i.tagName.toLowerCase(),
                    value: i.type === 'password' ? '' : String(i.value || '').slice(0, 200),
                })),
            }))
            """,
        )
    except Exception:  # noqa: BLE001
        forms = []

    try:
        title = page.title()
    except Exception:  # noqa: BLE001
        title = ""

    return title, same_domain_links, forms


def plan_next_url(state: GraphState) -> Optional[dict]:
    """Decide the next queued item to visit, or set crawl_stop_reason and return None.

    Hard overrides are checked first, with no LLM call, in this priority order:
    max_pages -> nothing queued within max_depth -> max_runtime -> diminishing returns.
    Only if none apply do we ask the LLM to prioritize among the queued URLs.
    """
    if len(state["pages_data"]) >= state["max_pages"]:
        state["crawl_stop_reason"] = "max_pages_reached"
        return None

    queued_within_depth = [item for item in state["queue"] if item["depth"] <= state["max_depth"]]
    if not queued_within_depth:
        state["crawl_stop_reason"] = "queue_empty" if not state["queue"] else "max_depth_reached"
        return None

    elapsed_minutes = (time.time() - state["crawl_start_time"]) / 60
    if elapsed_minutes >= state["max_runtime_minutes"]:
        state["crawl_stop_reason"] = "max_runtime_reached"
        return None

    if state["consecutive_low_value_visits"] >= 5:
        state["crawl_stop_reason"] = "diminishing_returns"
        return None

    verbose = state.get("verbose", True)

    summary = {
        "counts": {
            "visited": len(state["visited"]),
            "queued": len(state["queue"]),
            "pages_visited": len(state["pages_data"]),
            "api_calls_found": len(state["api_calls"]),
            "skipped_duplicate_patterns": len(state["skipped_duplicate_patterns"]),
        },
        "queued_sample": [
            {"url": item["url"], "depth": item["depth"], "pattern": item["pattern"]}
            for item in state["queue"][:15]
        ],
        "elapsed_minutes": round(elapsed_minutes, 1),
        "max_runtime_minutes": state["max_runtime_minutes"],
        "recent_pages": [
            {
                "title": p["title"],
                "form_count": len(p["forms"]),
                "new_link_count": p.get("new_link_count", 0),
            }
            for p in state["pages_data"][-3:]
        ],
    }
    prompt = f"""You are directing a web crawl for security-testing reconnaissance.

Current crawl state:
{json.dumps(summary, indent=2)}

Prioritize URLs suggesting admin panels, dashboards, account/profile/settings pages,
search/filter forms, or checkout/payment flows over generic content pages.

Respond with JSON only, one of:
{{"action": "choose_next_url", "url": "<a url that EXACTLY matches one currently in the queue>", "reason": "<short reason>"}}
{{"action": "stop_crawl", "stop_reason": "<queue_empty|max_pages_reached|max_depth_reached|max_runtime_reached|diminishing_returns|other>", "details": "<short>"}}
Stop only if the queue is empty or the budgets above are exhausted.
"""

    decision = ask_json(state["gateway"], "crawl_plan", prompt, CRAWL_PLAN_SCHEMA)

    chosen_item = None
    chosen_reason = ""
    if decision is None:
        state["warnings"].append({"event": "llm_call_failed", "details": "planner LLM call failed after retries"})
        chosen_item = queued_within_depth[0]
        chosen_reason = "FIFO fallback (planner LLM call failed)"
        if verbose:
            print(f"    [planner] LLM call failed, falling back to FIFO -> {chosen_item['url']}")
    else:
        name = decision.get("action")
        args = decision
        if name == "stop_crawl":
            reason = args.get("stop_reason") or "other"
            state["crawl_stop_reason"] = reason
            if verbose:
                print(f"    [planner] LLM requested stop: {reason} ({args.get('details', '')})")
            return None
        if name == "choose_next_url":
            candidate_url = normalize_url(args.get("url", ""), state["noise_params"])
            match = next((item for item in queued_within_depth if item["url"] == candidate_url), None)
            if match is not None:
                chosen_item = match
                chosen_reason = args.get("reason", "")
                if verbose:
                    print(f"    [planner] Chose {chosen_item['url']} — reason: '{chosen_reason}'")
            else:
                state["warnings"].append({
                    "event": "hallucinated_url",
                    "details": f"LLM chose '{args.get('url')}' which is not in the queue",
                })
                chosen_item = queued_within_depth[0]
                chosen_reason = "FIFO fallback (LLM chose a URL not in the queue)"
                if verbose:
                    print(f"    [planner] LLM chose a URL not in the queue, falling back to FIFO -> {chosen_item['url']}")
        else:
            state["warnings"].append({"event": "llm_call_failed", "details": f"unexpected planner action: {name}"})
            chosen_item = queued_within_depth[0]
            chosen_reason = "FIFO fallback (unexpected planner action)"

    state["queue"].remove(chosen_item)
    chosen_item = dict(chosen_item, reason=chosen_reason)
    return chosen_item


def visit_url(state: GraphState, item: dict) -> None:
    """Navigate to item['url'] (with retry/backoff), extract links/forms, and update state."""
    page = state["page"]
    url = item["url"]
    depth = item["depth"]
    pattern = item["pattern"]
    verbose = state.get("verbose", True)

    backoffs = [1, 2]
    navigated = False
    last_error = None
    for attempt in range(len(backoffs) + 1):
        try:
            page.goto(url, timeout=10_000)
            navigated = True
            break
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if attempt < len(backoffs):
                time.sleep(backoffs[attempt])

    if not navigated:
        state["failed_urls"].append({"url": url, "error": str(last_error)})
        state["consecutive_low_value_visits"] += 1
        if verbose:
            print(f"    Executing: page.goto('{url}')")
            print(f"    Failed to visit {url}: {last_error}")
        return

    try:
        # Client-rendered (React/Next.js SPA) pages often render partial content
        # (e.g. one link) immediately, then fetch data (e.g. the full nav menu)
        # asynchronously before rendering the rest. A selector wait can resolve
        # on that first partial render and miss everything else, so wait for
        # network activity to settle before extracting. Falls back to a plain
        # element wait if the app keeps some connection open indefinitely.
        page.wait_for_load_state("networkidle", timeout=8_000)
    except Exception:  # noqa: BLE001
        try:
            page.wait_for_selector("a, form, button", timeout=3_000)
        except Exception:  # noqa: BLE001
            pass

    title, links, forms = extract_links_and_forms(page, state["crawl_start_url"], state["same_domain_mode"])

    screenshot_name = save_page_screenshot(state, page, f"{len(state['pages_data'])}.jpg", log=False)

    state["visited"].add(url)
    state["pattern_counts"][pattern] = state["pattern_counts"].get(pattern, 0) + 1

    new_link_count = 0
    for link in links:
        try:
            normalized_link = normalize_url(link, state["noise_params"])
        except Exception:  # noqa: BLE001
            continue
        if normalized_link in state["visited"]:
            continue
        if any(q["url"] == normalized_link for q in state["queue"]):
            continue
        link_pattern = get_url_pattern(normalized_link)
        if state["pattern_counts"].get(link_pattern, 0) < state["max_per_pattern"]:
            if depth + 1 <= state["max_depth"]:
                state["queue"].append({"url": normalized_link, "depth": depth + 1, "pattern": link_pattern})
                new_link_count += 1
            # else: beyond configured crawl depth, silently not queued
        else:
            state["skipped_duplicate_patterns"].append({
                "url": normalized_link, "pattern": link_pattern, "reason": "max_per_pattern_reached",
            })

    state["pages_data"].append({
        "url": url, "depth": depth, "title": title,
        "forms": forms, "links": links, "new_link_count": new_link_count,
        "screenshot": screenshot_name,
    })

    if new_link_count == 0 and not forms:
        state["consecutive_low_value_visits"] += 1
    else:
        state["consecutive_low_value_visits"] = 0

    if verbose:
        print(f"    Executing: page.goto('{url}')")
        print(f"[{len(state['pages_data'])}/{state['max_pages']}] Visiting {url} "
              f"(depth {depth}, pattern {pattern}) — agent reason: '{item.get('reason', '')}' "
              f"— found {len(forms)} forms, {new_link_count} new links queued")
        if screenshot_name:
            print(f"    [screenshot: {screenshot_name}]")

    time.sleep(1)  # politeness delay


def print_crawl_summary(state: GraphState) -> None:
    print("\n[4/4] Crawl finished.")
    print(f"  Pages visited: {len(state['pages_data'])}")
    print(f"  Duplicate-pattern pages skipped: {len(state['skipped_duplicate_patterns'])}")
    print(f"  Forms found: {sum(len(p['forms']) for p in state['pages_data'])}")
    print(f"  Unique API endpoints found: {len(state['api_calls'])}")
    print(f"  Failed URLs: {len(state['failed_urls'])}")
    print(f"  Warnings: {len(state['warnings'])}")
    print(f"  Stop reason: {state['crawl_stop_reason']}")

    if state["pages_data"]:
        print("\n  Discovered pages:")
        for p in state["pages_data"]:
            print(f"    [depth {p['depth']}] {p['url']}  (title: '{p['title']}', forms: {len(p['forms'])})")

    if state["api_calls"]:
        print("\n  Discovered API endpoints:")
        for call in state["api_calls"]:
            print(f"    {call['method']} {call['url']}  (status {call['status_code']}, {call['content_type']})")

    if state["skipped_duplicate_patterns"]:
        print("\n  Skipped (duplicate pattern):")
        for s in state["skipped_duplicate_patterns"]:
            print(f"    {s['url']}  (pattern: {s['pattern']}, reason: {s['reason']})")

    if state["failed_urls"]:
        print("\n  Failed URLs:")
        for f in state["failed_urls"]:
            print(f"    {f['url']}  ({f['error']})")

    if state["warnings"]:
        print("\n  Warnings:")
        for w in state["warnings"]:
            print(f"    [{w['event']}] {w['details']}")


def crawl(state: GraphState) -> GraphState:
    resuming = bool(state["visited"] or state["queue"])
    # Network capture hangs off a browser context. A resume after re-login runs in a *new*
    # context, so attach to whichever context the page belongs to now, once per context.
    context = state["page"].context
    if state.get("_capture_context") is not context:
        setup_network_capture(context, state)
        state["_capture_context"] = context
    if resuming:
        print("\n[4/4] Resuming crawl after session recovery...")
    else:
        print("\n[4/4] Starting crawl...")
        state["crawl_start_time"] = time.time()
        start_normalized = normalize_url(state["crawl_start_url"], state["noise_params"])
        state["queue"] = [{
            "url": start_normalized,
            "depth": 0,
            "pattern": get_url_pattern(start_normalized),
        }]

    # Internal loop: plan_next_url() picks the next URL (LLM-directed, with hard
    # budget overrides and FIFO fallbacks on LLM failure/hallucination), and
    # visit_url() executes that visit and updates state in place. This stays a
    # plain Python loop inside one node rather than separate graph nodes/edges,
    # since each iteration is the same two-step operation on the same state,
    # not a distinct pipeline phase - see the design note in the module docstring.
    #
    # Heartbeat: an app can bounce the session back to the login page mid-crawl
    # (expired session, server restart, etc). login_url is only set when we
    # actually drove an interactive login (not --storage-state), since that's
    # the only case where re-login is even possible. Detecting this here and
    # stopping with "session_lost" lets the graph route back to the login node
    # for one bounded recovery attempt (see route_after_crawl in graph.py)
    # instead of silently crawling logged-out pages for the rest of the budget.
    while True:
        abort = state.get("should_abort")
        if abort is not None and abort():
            state["crawl_stop_reason"] = "cancelled"
            break
        item = plan_next_url(state)
        if item is None:
            break
        visit_url(state, item)
        if state["login_url"] and not looks_logged_in(state["page"], state["login_url"]):
            state["crawl_stop_reason"] = "session_lost"
            state["warnings"].append({"event": "session_lost", "details": f"Bounced back to a login-shaped page after visiting {item['url']}"})
            break
        # Identities with no login page to bounce back to (a token, a saved session) lose their
        # session as a run of 401/403s; the discover stage supplies the check.
        loss_check = state.get("session_lost_check")
        reason = loss_check() if loss_check else ""
        if reason:
            state["crawl_stop_reason"] = "session_lost"
            state["warnings"].append({"event": "session_lost", "details": f"{reason} (after visiting {item['url']})"})
            break

    print_crawl_summary(state)
    return state
