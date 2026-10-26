# TLS certificate hostname mismatch

## What it means

The certificate the server presented does not cover the hostname the request was made to (it was issued for a different name, or lacks a matching Subject Alternative Name entry), so clients that properly validate certificates will reject the connection.

## How to fix it

- Reissue the certificate with the correct hostname, or every hostname actually served, listed in its Subject Alternative Name entries.
- If this host is served behind a load balancer or CDN, confirm the certificate installed there actually matches every hostname it terminates TLS for.

## Verify

Re-run the scan after reissuing the certificate and confirm the finding no longer appears.
