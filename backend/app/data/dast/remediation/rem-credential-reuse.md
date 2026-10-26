# Shared session across identities

## What it means

Two identities presented the same session cookie value.

## How to fix it

Issue a distinct session per login. Do not copy cookies between accounts.

## Verify

Authenticate each identity again and compare the cookie values.
