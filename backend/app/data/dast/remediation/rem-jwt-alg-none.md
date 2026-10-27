# JWT alg none

Configure a fixed allowlist of signed JWT algorithms in the verifier. Reject `none` and missing signatures before reading identity or privilege claims. Verify the signature using the trusted issuer key; never select verification policy from an untrusted token header. Confirm that unsigned variants are refused on every protected endpoint.
