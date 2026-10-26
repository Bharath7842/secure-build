# Excessive data exposure

## What it means

Responses include more properties than the client needs, such as internal ids, hashes or personal data.

## How to fix it

- Return explicit response DTOs that list only the fields the operation needs.
- Do not rely on the client to hide fields.
- Review serializers whenever a model gains a new column.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test for the behaviour you changed.
