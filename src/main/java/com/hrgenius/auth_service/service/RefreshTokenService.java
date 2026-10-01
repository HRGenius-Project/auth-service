package com.hrgenius.auth_service.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private static final String PREFIX = "refresh:";

    private final StringRedisTemplate redis;

    @Value("${jwt.refresh-expiry-days}")
    private long refreshExpiryDays;

    public String create(Long userId) {
        String token = UUID.randomUUID().toString();
        redis.opsForValue().set(PREFIX + token, String.valueOf(userId), Duration.ofDays(refreshExpiryDays));
        return token;
    }

    public Optional<Long> validate(String token) {
        String value = redis.opsForValue().get(PREFIX + token);
        return value == null ? Optional.empty() : Optional.of(Long.parseLong(value));
    }

    public void delete(String token) {
        redis.delete(PREFIX + token);
    }
}