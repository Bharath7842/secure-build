# DAST Passive Crawl Discovery Design

## Goal

Prevent the DAST discovery crawler from clicking arbitrary interactive controls while it extracts links and forms. This removes the specific self-inflicted logout path without claiming that ordinary page navigation can never execute target-side behavior.

## Observed failure

During scan `4206f141-4af0-4652-822a-a21217c2668c`, the crawler authenticated successfully and loaded protected employee data. Its interactive-element discovery then clicked the `EN` and `FR` language buttons. The language change renamed the visible `Logout` button to `Déconnexion`, which bypassed the crawler's English destructive-text filter. The next generic button probe clicked it and the browser sent `POST /api/auth/logout`, receiving HTTP 204. The crawler subsequently reported that the session was lost.

The target did not spontaneously expire the session. The crawler caused the logout.

## Chosen approach

Crawl extraction will be non-interactive:

- Extract and queue same-scope destinations from actual anchors with `href` values.
- Extract forms without submitting them.
- Keep the existing API traffic capture and JavaScript/schema discovery stages.
- Do not click generic `button`, `[role="button"]`, `[role="link"]`, or `[onclick]` elements while discovering routes.

The existing destructive URL/text filter remains useful for anchors, but it is not treated as a complete classifier. It cannot reliably recognize every language, icon-only control, or application-specific destructive action. Navigating queued anchors remains a separate, bounded crawl behavior; this change does not promise that a hostile or incorrectly designed GET route is side-effect free.

## Alternatives rejected

### Add multilingual destructive words

This fixes only known translations and fails for icon buttons, custom labels, and languages not included in the list.

### Click controls in a temporary page and restore afterward

A temporary page still shares server-side session identifiers and can trigger irreversible server-side effects. Restoring browser URL or cookies cannot undo a logout, delete, payment, or other mutation already accepted by the server.

### Abort only state-changing network methods during button probes

This still permits client-side state corruption and unsafe applications that mutate on GET. It also duplicates the safety policy at the crawl layer. Passive discovery has a smaller and clearer trust boundary.

## Code changes

`backend/app/dast/nodes/crawl.py` will stop invoking interactive-element click discovery from `extract_links_and_forms`. The now-unused click-probing selector and helper will be removed. Anchor discovery, form extraction, screenshots, network capture, crawl planning, and session checks remain unchanged.

Unit tests will exercise the public extraction behavior with a page fake that contains anchors, forms, and clickable buttons. They will prove that:

1. anchor destinations and forms are still returned;
2. no clickable element is clicked, including language and localized logout controls;
3. destructive anchors remain excluded by the existing filter.

A real-browser integration regression will extend the local live-site fixture with the incident sequence: `EN`, `FR`, and a logout control whose text changes to `Déconnexion`. The logout handler will invalidate the fixture session if called. The test will run discovery with state-changing requests otherwise permitted and assert:

- the server receives zero logout requests;
- a protected identity endpoint still returns HTTP 200 after extraction; and
- the scan does not enter session recovery because of its own UI probing.

For this test, "session remains usable" means that the same identity's browser context can make a successful authenticated request to the fixture's protected identity endpoint after extraction.

## Behavior and trade-off

Button-only client-side routes may no longer be learned during the browser crawl. This is an intentional safety trade-off: incomplete non-interactive discovery is preferable to mutating an application or invalidating the identity being scanned. Existing script harvesting, observed network traffic, schemas, and ordinary links continue to supply additional coverage.

## Success criteria

- Reproducing the employee-app control sequence does not produce `POST /api/auth/logout` during crawl discovery.
- The same authenticated browser context receives HTTP 200 from a protected identity endpoint after link/form extraction.
- Existing anchor and form discovery behavior remains covered and passing.
- Focused crawler tests and the relevant backend test suite pass.

## Non-goals

- Changing the employee application.
- Expanding the destructive-word dictionary.
- Building a sandbox for active UI exploration.
- Changing the separate session-loss verdict work.
