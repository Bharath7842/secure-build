# Unrestricted resource consumption

## What it means

The endpoint does not limit request rate, payload size or work per request, so a single caller can exhaust capacity.

## How to fix it

- Apply rate limits per identity and per client address.
- Cap request body size, page size, nesting depth and upload size.
- Set timeouts and concurrency limits on expensive operations.
- Monitor and alert on unusual consumption.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test for the behaviour you changed.
