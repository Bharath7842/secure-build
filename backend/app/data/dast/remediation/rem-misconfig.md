# Security misconfiguration

## What it means

Security headers are missing or weak, unnecessary methods are enabled, or debug features are exposed.

## How to fix it

- Set the standard security headers (CSP, HSTS, X-Content-Type-Options, frame protection) at the edge or framework level.
- Disable methods and debug endpoints that are not needed.
- Harden configuration in code and verify it in CI.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test for the behaviour you changed.
