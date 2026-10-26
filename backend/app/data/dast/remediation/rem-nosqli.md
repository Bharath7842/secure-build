# NoSQL injection

## What it means

User input reached a document or key-value store's query as live query structure (an operator like `$ne`/`$where`, or a raw query fragment) rather than as a plain value.

## How to fix it

- Build queries with the driver's own query-builder or parameter binding; never interpolate input into a raw query string or pass it through as an object that could carry operators.
- Reject input that is not the scalar type a field expects (e.g. a string field must not accept an object) before it reaches the query.
- Run the application with a database account that has only the privileges it needs.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test asserting an operator-shaped input is treated as a literal value, not query structure.
