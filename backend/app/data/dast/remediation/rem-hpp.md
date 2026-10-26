# HTTP parameter pollution

## What it means

A duplicate parameter's second value was the one the application used.

## How to fix it

Reject duplicate parameters, or define and test which occurrence wins. Do not let a second copy override a security-relevant value.

## Verify

Repeat the request with the parameter twice and confirm the original value is the one applied.
