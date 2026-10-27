# JWT weak secret

Replace tutorial/default signing secrets with a randomly generated key of sufficient size for the selected HMAC algorithm. Keep keys in a secret manager, rotate the affected key, and invalidate existing tokens. The scanner only checks five fixed public examples when explicitly enabled; no match does not establish key strength.
