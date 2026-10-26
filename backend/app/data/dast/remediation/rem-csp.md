# Missing Content-Security-Policy

## What it means

No Content-Security-Policy header limits which sources scripts and other content may load from.

## How to fix it

- Send a Content-Security-Policy header starting from `default-src 'self'` and relax only what the application needs.
- Avoid `unsafe-inline` and `unsafe-eval`; use nonces or hashes for inline script.
- Deploy in report-only mode first, then enforce.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test for the behaviour you changed.
