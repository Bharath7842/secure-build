# Self-signed TLS certificate

## What it means

The certificate was not issued by a certificate authority a standard trust store recognizes, so every client either rejects the connection outright or must be specially configured to trust it - and an attacker who can intercept traffic could present their own self-signed certificate just as easily.

## How to fix it

- Obtain a certificate from a publicly trusted CA (e.g. via ACME/Let's Encrypt) for anything reachable from the public internet or from clients you do not control.
- A self-signed certificate is reasonable only for internal services where every client is deliberately configured to pin or trust it - confirm that is actually the case here before dismissing this.

## Verify

Re-run the scan after installing a CA-issued certificate and confirm the finding no longer appears.
