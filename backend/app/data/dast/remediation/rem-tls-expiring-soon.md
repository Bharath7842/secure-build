# TLS certificate expiring soon

## What it means

The certificate the server presented is still valid but expires within 30 days.

## How to fix it

- Renew the certificate now rather than waiting for expiry, and automate renewal (e.g. ACME/Let's Encrypt, or your CA's auto-renewal) so this cannot recur.
- Monitor certificate expiry separately from this scan.

## Verify

Re-run the scan after renewing the certificate and confirm the finding no longer appears.
