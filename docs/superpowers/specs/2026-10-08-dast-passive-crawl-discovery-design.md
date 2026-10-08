# DAST Passive Crawl Discovery Design

## Goal

Prevent the DAST discovery crawler from changing target state or destroying its own authenticated session while it discovers pages.

## Observed failure

During scan `4206f141-4af0-4652-822a-a21217c2668c`, the crawler authenticated successfully and loaded protected employee data. Its interactive-element discovery then clicked the `EN` and `FR` language buttons. The language change renamed the visible `Logout` button to `Déconnexion`, which bypassed the crawler's English destructive-text filter. The next generic button probe clicked it and the browser sent `POST /api/auth/logout`, receiving HTTP 204. The crawler subsequently reported that the session was lost.

The target did not spontaneously expire the session. The crawler caused the logout.

## Chosen approach

Crawl discovery will be passive:

- Extract and queue same-scope destinations from actual anchors with `href` values.
- Extract forms without submitting them.
- Keep the existing API traffic capture and JavaScript/schema discovery stages.
- Do not click generic `button`, `[role="button"]`, `[role="link"]`, or `[onclick]` elements while discovering routes.

The existing destructive URL/text filter remains useful for anchors, but it is not treated as a complete classifier. It cannot reliably recognize every language, icon-only control, or application-specific destructive action.

## Alternatives rejected

### Add multilingual destructive words

This fixes only known translations and fails for icon buttons, custom labels, and languages not included in the list.

### Click controls in a temporary page and restore afterward

A temporary page still shares server-side session identifiers and can trigger irreversible server-side effects. Restoring browser URL or cookies cannot undo a logout, delete, payment, or other mutation already accepted by the server.

### Abort only state-changing network methods during button probes

This still permits client-side state corruption and unsafe applications that mutate on GET. It also duplicates the safety policy at the crawl layer. Passive discovery has a smaller and clearer trust boundary.

## Code changes

`backend/app/dast/nodes/crawl.py` will stop invoking interactive-element click discovery from `extract_links_and_forms`. The now-unused click-probing selector and helper will be removed. Anchor discovery, form extraction, screenshots, network capture, crawl planning, and session checks remain unchanged.

Tests will exercise the public extraction behavior with a page fake that contains anchors, forms, and clickable buttons. They will prove that:

1. anchor destinations and forms are still returned;
2. no clickable element is clicked, including language and localized logout controls;
3. destructive anchors remain excluded by the existing filter.

## Behavior and trade-off

Button-only client-side routes may no longer be learned during the browser crawl. This is an intentional safe-mode trade-off: incomplete passive discovery is preferable to mutating an application or invalidating the identity being scanned. Existing script harvesting, observed network traffic, schemas, and ordinary links continue to supply additional coverage.

## Success criteria

- Reproducing the employee-app page does not produce `POST /api/auth/logout` during crawl discovery.
- The authenticated browser session remains usable after link/form extraction.
- Existing anchor and form discovery behavior remains covered and passing.
- Focused crawler tests and the relevant backend test suite pass.

## Non-goals

- Changing the employee application.
- Expanding the destructive-word dictionary.
- Building a sandbox for active UI exploration.
- Changing the separate session-loss verdict work.
