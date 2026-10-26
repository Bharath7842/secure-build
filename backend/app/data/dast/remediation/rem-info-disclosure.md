# Information disclosure through errors

## What it means

Error responses expose stack traces, database messages or internal paths.

## How to fix it

- Return a generic message and a correlation id to the client; log the detail server-side.
- Disable debug mode and framework error pages in production.
- Add a catch-all handler so unhandled exceptions never reach the client unformatted.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test for the behaviour you changed.
