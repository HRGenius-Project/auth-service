package com.hrgenius.auth_service.security;

import com.hrgenius.auth_service.entity.Role;
import com.hrgenius.auth_service.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Service
public class JwtService {

    private final SecretKey key;
    private final long accessExpiryMinutes;

    public JwtService(@Value("${jwt.secret}") String secret,
                      @Value("${jwt.access-expiry-minutes}") long accessExpiryMinutes) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessExpiryMinutes = accessExpiryMinutes;
    }

    public String generateAccessToken(User user) {
        Date now = new Date();
        // pehle login pe password badalna zaroori ho to roles khali (limited token)
        List<String> roles = user.isMustChangePassword()
                ? List.of()
                : user.getRoles().stream().map(Role::getName).toList();
        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(user.getUsername())
                .claim("userId", user.getId())
                .claim("roles", roles)
                .issuedAt(now)
                .expiration(new Date(now.getTime() + accessExpiryMinutes * 60_000))
                .signWith(key)
                .compact();
    }

    public Claims parse(String token) {
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();
    }

    public long getAccessExpirySeconds() {
        return accessExpiryMinutes * 60;
    }
}