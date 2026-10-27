# JWT missing claims

Require and validate exp, iss and aud before granting access. Enforce expiry, pin the expected issuer and audience, and verify the signature with an allowlisted algorithm and a trusted key. A signature failure can prevent the scanner from exercising claim validation independently; rejection of its probe alone does not prove correct claim validation.
