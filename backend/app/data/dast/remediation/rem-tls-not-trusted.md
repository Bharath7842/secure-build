# TLS certificate not trusted

## What it means

A standard trust store could not validate the certificate chain the server presented, for a reason other than expiry, self-signing or a hostname mismatch (commonly a missing intermediate certificate).

## How to fix it

- Confirm the server sends its full certificate chain, including any intermediate certificates, not just the leaf certificate.
- Confirm the issuing CA is still a member of the standard trust stores your clients use.

## Verify

Re-run the scan after fixing the chain and confirm the finding no longer appears; confirm with your TLS stack's own test tool that the chain now validates.
