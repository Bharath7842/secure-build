# XML external entity injection

## What it means

The XML parser expanded an entity from request data.

## How to fix it

Disable external entities and DTD processing in every XML parser. Prefer a format that is not XML for untrusted input.

## Verify

Send the same document again and confirm the entity text is not in the response.
