# Cross-site scripting

## What it means

Input is reflected into a page without escaping, so attacker-supplied markup runs in the victim's browser.

## How to fix it

- Escape output for its context (HTML body, attribute, JavaScript, URL) using the framework's templating defaults.
- Do not disable auto-escaping; avoid inserting untrusted data with innerHTML.
- Add a Content-Security-Policy that blocks inline script as a second layer.
- Set cookies HttpOnly so script cannot read them.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test for the behaviour you changed.
