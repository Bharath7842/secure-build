# Session management

## What it means

A session token remains valid after logout, password change or expiry.

## How to fix it

- Invalidate sessions server-side on logout and credential change.
- Use short idle and absolute timeouts.
- Rotate the session identifier on login and privilege change.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test for the behaviour you changed.
