# Expired TLS certificate

## What it means

The certificate the server presented has passed its expiry date. Browsers and API clients will refuse or warn on every connection until it is replaced.

## How to fix it

- Renew the certificate before it expires, and automate renewal (e.g. ACME/Let's Encrypt, or your CA's auto-renewal) so this cannot recur.
- Monitor certificate expiry separately from this scan; a 30+ day advance alert is standard practice.

## Verify

Re-run the scan after renewing the certificate and confirm the finding no longer appears.
