# Ambiguous request framing

## What it means

A request that set both Content-Length and Transfer-Encoding was accepted.

## How to fix it

Reject requests that carry both framing headers. Keep a single HTTP parser in front of the application.

## Verify

Send one request with both headers and confirm a 4xx.
