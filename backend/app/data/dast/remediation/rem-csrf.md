# Cross-site request forgery (CSRF)

## What it means

A state-changing request succeeded without a valid anti-CSRF token, so a page on another site could trigger the same action using the victim's own session.

## How to fix it

- Require a per-session (or per-request) anti-CSRF token on every state-changing request, and reject the request outright when it is missing or does not match.
- Verify the token server-side before any side effect runs, not after.
- Set the session cookie's `SameSite` attribute to `Lax` or `Strict` as a second layer of defense, not a replacement for the token.
- For APIs consumed only by your own JavaScript, consider requiring a custom request header that a cross-site form submission cannot set.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test asserting the request is rejected when the token is missing or invalid.
