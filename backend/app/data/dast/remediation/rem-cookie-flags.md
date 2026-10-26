# Cookie attributes

## What it means

A session or sensitive cookie lacks HttpOnly, Secure or SameSite, which weakens its protection against theft and cross-site use.

## How to fix it

- Set `HttpOnly` so script cannot read the cookie.
- Set `Secure` so it is sent only over HTTPS.
- Set `SameSite=Lax` or `Strict` unless cross-site use is required.
- Use the `__Host-` prefix for session cookies where possible.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test for the behaviour you changed.
