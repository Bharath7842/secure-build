# Exceptional condition handling

## What it means

Unusual or oversized input crashes the service or produces inconsistent behaviour.

## How to fix it

- Set maximum sizes for bodies, fields and nesting.
- Handle exceptions at a boundary and return a controlled error.
- Fuzz the endpoint in CI with malformed input and assert it fails cleanly.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test for the behaviour you changed.
