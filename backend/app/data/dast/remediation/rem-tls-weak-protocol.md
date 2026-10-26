# Deprecated TLS protocol version

## What it means

The server accepted a connection using SSLv2, SSLv3, TLS 1.0 or TLS 1.1 - versions every major browser has removed support for and that carry known protocol-level weaknesses.

## How to fix it

- Disable every protocol version below TLS 1.2 in the web server or load balancer's TLS configuration.
- Prefer TLS 1.3 where your clients support it.
- Re-check any dependent internal service or legacy client that may have required the old version before disabling it.

## Verify

Re-run the scan and confirm the finding no longer appears; confirm with your TLS stack's own test tool (e.g. `openssl s_client -tls1_1`) that the old version is now refused.
