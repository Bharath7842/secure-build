# Missing Strict-Transport-Security

## What it means

Without HSTS a browser may be downgraded to plain HTTP by a network attacker.

## How to fix it

- Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on every HTTPS response.
- Redirect all HTTP traffic to HTTPS.
- Consider preload once every subdomain supports HTTPS.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test for the behaviour you changed.
