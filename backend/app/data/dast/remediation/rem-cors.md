# CORS policy

## What it means

The server allows other origins to read authenticated responses.

## How to fix it

- Allow only specific, trusted origins; never reflect the request Origin without checking it against a list.
- Never combine a wildcard origin with credentials.
- Restrict allowed methods and headers to what is needed.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test for the behaviour you changed.
