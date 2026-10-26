# Sensitive path reachable

## What it means

A well-known path returned its own document.

## How to fix it

Remove the file or endpoint, or require authentication and do not serve it from the web root.

## Verify

Request the same path again and confirm it is gone or refused.
