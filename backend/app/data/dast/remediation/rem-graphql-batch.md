# GraphQL batching enabled

## What it means

The endpoint accepted an array of operations.

## How to fix it

Reject batched queries, or cap the array length and the cost of the batch.

## Verify

POST a two-element array and confirm it is refused.
