# Broken object level authorization

## What it means

The API returns an object based on an identifier the caller supplies without checking that the caller may access that object.

## How to fix it

- Enforce an ownership or permission check on every request that takes an object id, server-side, in a shared layer rather than per handler.
- Use the authenticated principal, not a client-supplied user id, to scope queries.
- Prefer unguessable identifiers (UUIDs) as defence in depth; they do not replace the check.
- Add tests that request another user's object and expect a 403 or 404.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test for the behaviour you changed.
