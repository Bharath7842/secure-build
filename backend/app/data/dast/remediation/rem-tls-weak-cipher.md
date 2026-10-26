# Weak TLS cipher suite

## What it means

The server negotiated a cipher suite built on a broken or deprecated algorithm (RC4, 3DES, a NULL cipher, an export-grade suite, or MD5), which a sufficiently motivated attacker can exploit to recover plaintext.

## How to fix it

- Configure the web server or load balancer's cipher list to only offer modern AEAD suites (e.g. the ECDHE-*-GCM / ChaCha20-Poly1305 families) and remove the weak ones entirely rather than merely de-prioritizing them.
- Prefer TLS 1.3, which removes the weak cipher families from the protocol entirely.

## Verify

Re-run the scan and confirm the finding no longer appears; confirm with your TLS stack's own test tool that the weak suite is now refused.
