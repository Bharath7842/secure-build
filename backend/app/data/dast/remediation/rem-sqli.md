# SQL injection

## What it means

User input is concatenated into a database query, so an attacker can change the query.

## How to fix it

- Use parameterized queries or prepared statements for every query; never build SQL from strings containing input.
- Use an ORM's parameter binding, and avoid raw SQL fragments from input.
- Run the application with a database account that has only the privileges it needs.
- Return generic errors and log details server-side.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test for the behaviour you changed.
