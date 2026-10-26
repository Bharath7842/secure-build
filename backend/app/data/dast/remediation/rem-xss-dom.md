# DOM-based cross-site scripting

## What it means

Client-side code takes a URL parameter or a field the user typed and inserts it into the page as HTML or script. The scan's marker ran in the browser, or reached a markup sink.

## How to fix it

- Treat location, document.referrer and field values as data. Insert them with textContent or a framework binding that escapes, not innerHTML, outerHTML, document.write or eval.
- Do not build script from strings (setTimeout with a string, new Function, eval).
- Add a Content-Security-Policy that blocks inline script, as a second layer.

## Verify

Re-run the scan and confirm the marker no longer executes. Add a regression test that renders the same input as text.
