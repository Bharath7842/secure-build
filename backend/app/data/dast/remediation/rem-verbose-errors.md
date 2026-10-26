# Verbose errors

## What it means

Responses expose stack traces, SQL errors or file paths.

## How to fix it

- Return generic error bodies with a correlation id.
- Log full detail server-side only.
- Disable debug mode in production.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test for the behaviour you changed.
