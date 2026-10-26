# Unsafe consumption of APIs

## What it means

Data from third-party APIs is trusted as if it were internal and reaches interpreters or storage unvalidated.

## How to fix it

- Validate and sanitize data received from upstream services as strictly as user input.
- Enforce TLS and timeouts for upstream calls and limit redirects.
- Treat upstream failures as expected and handle them safely.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test for the behaviour you changed.
