# HTML injection

## What it means

Input is reflected into a page without escaping. Even without a working script payload, injected markup can rewrite the page's content, add fake forms, or redirect links.

## How to fix it

- Escape output for its context (HTML body, attribute, URL) using the framework's templating defaults; do not disable auto-escaping.
- Avoid inserting untrusted data with `innerHTML` or an equivalent raw-markup sink.
- Add a Content-Security-Policy as a second layer of defense.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test asserting markup characters in input are escaped, not rendered.
