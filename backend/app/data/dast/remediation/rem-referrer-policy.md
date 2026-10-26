# Missing Referrer-Policy

## What it means

Without a Referrer-Policy header, browsers may send the full URL of a page (including query strings that can carry identifiers or tokens) to every site the page links to or loads from.

## How to fix it

- Send `Referrer-Policy: strict-origin-when-cross-origin` (or `no-referrer` where links never need it).
- Do not put secrets or session identifiers in URLs; use headers or request bodies instead.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test for the behaviour you changed.
