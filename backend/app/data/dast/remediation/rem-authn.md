# Broken authentication

## What it means

A protected endpoint can be reached with no credentials, an expired token or an invalid one.

## How to fix it

- Require authentication by default and opt endpoints out explicitly, rather than the reverse.
- Validate token signature, issuer, audience and expiry on every request.
- Return 401 for missing or invalid credentials and never serve the protected body.
- Add a regression test that calls each protected route without credentials.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test for the behaviour you changed.
