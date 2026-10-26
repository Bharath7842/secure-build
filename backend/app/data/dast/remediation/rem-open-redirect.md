# Open redirect

## What it means

A parameter controls where the application redirects the browser, and the server accepted an attacker-chosen, off-site destination.

## How to fix it

- Never redirect to a URL taken directly from input. Redirect to a fixed set of allowed destinations (an allowlist of paths or a lookup table keyed by a short code).
- If an external redirect is genuinely needed, validate the destination against an allowlist of trusted hosts before redirecting.
- Where possible, redirect to a relative path only, so the browser cannot be sent off-site at all.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test asserting an off-allowlist destination is rejected.
