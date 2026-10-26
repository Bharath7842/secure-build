# Clickjacking protection

## What it means

Another site can embed the page in a frame and trick users into clicking.

## How to fix it

- Send `Content-Security-Policy: frame-ancestors 'self'` (or 'none').
- Send `X-Frame-Options: DENY` or SAMEORIGIN for older browsers.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test for the behaviour you changed.
