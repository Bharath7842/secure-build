# GraphQL introspection enabled

## What it means

The endpoint returned its schema.

## How to fix it

Disable introspection outside development, or require an authenticated role that production clients do not have.

## Verify

Send an introspection query and confirm it is refused.
