# Sensitive business flows

## What it means

Flows such as purchase, signup, invitation or password reset can be abused at scale even when every call is individually valid.

## How to fix it

- Identify the flows whose abuse has business impact and review them with the product owner.
- Add flow-aware limits: per-account and per-device quotas, step ordering, human verification where justified.
- Monitor for automation patterns on those flows.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test for the behaviour you changed.
