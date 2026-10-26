# LDAP injection

## What it means

User input was concatenated directly into an LDAP search filter, so an attacker could change what the filter matches.

## How to fix it

- Escape every special LDAP filter character in input (`\`, `*`, `(`, `)`, NUL) before building a filter, following RFC 4515.
- Prefer a library that builds filters from structured values rather than string concatenation.
- Run the directory bind with an account that has only the read access it needs.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test asserting filter metacharacters in input are escaped rather than interpreted.
