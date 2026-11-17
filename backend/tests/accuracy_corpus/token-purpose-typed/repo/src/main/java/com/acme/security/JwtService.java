package com.acme.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.Date;

public class JwtService {
    private final String secret = System.getenv("JWT_SECRET");

    public String generateAccessToken(String username) {
        return Jwts.builder().setSubject(username).claim("token_use", "access")
                .setExpiration(new Date(System.currentTimeMillis() + 15L * 60 * 1000))
                .signWith(SignatureAlgorithm.HS256, secret).compact();
    }

    public String generateRefreshToken(String username) {
        return Jwts.builder().setSubject(username).claim("token_use", "refresh")
                .setExpiration(new Date(System.currentTimeMillis() + 30L * 24 * 3600 * 1000))
                .signWith(SignatureAlgorithm.HS256, secret).compact();
    }

    public String accessSubject(String token) {
        Claims claims = Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
        if (!"access".equals(claims.get("token_use"))) {
            throw new IllegalArgumentException("not an access token");
        }
        return claims.getSubject();
    }
}
