# Mass assignment

## What it means

The server binds request properties directly onto internal objects, so a caller can set fields such as roles or ownership that the client never sends.

## How to fix it

- Bind requests to an explicit allow-list of writable properties (a request DTO), not the persistence model.
- Reject unknown properties instead of ignoring them.
- Keep privileged fields (role, isAdmin, ownerId) out of any model that accepts client input.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test for the behaviour you changed.
