# XPath injection

## What it means

User input was concatenated directly into an XPath expression, so an attacker could change which nodes the expression selects.

## How to fix it

- Use parameterized XPath (`XPathExpression` with variable bindings, or an equivalent in your XML library) instead of building the expression as a string.
- If concatenation cannot be avoided, escape quotes and reject the limited set of XPath metacharacters the function used does not already handle.
- Apply the principle of least privilege to whatever the XML document or store exposes.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test asserting metacharacters in input do not change which nodes are selected.
