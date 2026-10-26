# Input validation

## What it means

Unexpected types, sizes or characters are accepted and change behaviour.

## How to fix it

- Validate type, length, range and format on the server for every input, using an allow-list where possible.
- Reject invalid input with a clear 4xx rather than processing it.
- Validate at the boundary and again before use in sensitive operations.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test for the behaviour you changed.
