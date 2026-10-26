# Broken function level authorization

## What it means

A privileged function (administration, bulk actions) can be called by an identity that should not have access.

## How to fix it

- Deny by default and require an explicit role or permission for every function.
- Centralize the authorization check in middleware or a policy layer.
- Do not rely on hidden URLs or UI hiding to protect admin functions.
- Test every privileged route as a lower-privilege user and as anonymous.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test for the behaviour you changed.
