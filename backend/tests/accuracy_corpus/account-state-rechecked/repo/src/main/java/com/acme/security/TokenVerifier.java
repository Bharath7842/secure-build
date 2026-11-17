package com.acme.security;

public class TokenVerifier {
    public String usernameFor(String token) {
        return token == null ? null : token.split(":")[0];
    }
}
