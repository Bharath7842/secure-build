# Sensitive data in responses

## What it means

Responses contain secrets, tokens, keys or personal data that the caller does not need.

## How to fix it

- Remove the data from the response, or mask it.
- Never return password hashes, tokens or keys from application endpoints.
- Rotate any secret that was exposed.
- Review serializers and logging so the same data does not leak elsewhere.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test for the behaviour you changed.
