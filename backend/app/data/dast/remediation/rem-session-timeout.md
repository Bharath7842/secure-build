# Long-lived session cookie

## What it means

The cookie stays valid for more than a day.

## How to fix it

Set a short Max-Age and expire idle server sessions independently of the cookie.

## Verify

Inspect the Set-Cookie lifetime after login.
