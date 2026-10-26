# Missing X-Content-Type-Options

## What it means

Browsers may guess a response's content type and execute content as script.

## How to fix it

- Send `X-Content-Type-Options: nosniff` on all responses.
- Always set an accurate Content-Type.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test for the behaviour you changed.
