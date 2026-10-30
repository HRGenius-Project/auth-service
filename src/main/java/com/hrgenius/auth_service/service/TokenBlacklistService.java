package com.hrgenius.auth_service.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class TokenBlacklistService {

    private static final String PREFIX = "blacklist:";

    private final StringRedisTemplate redis;

    public void blacklist(String jti, Duration ttl) {
        if (jti != null && !ttl.isNegative() && !ttl.isZero()) {
            redis.opsForValue().set(PREFIX + jti, "1", ttl);
        }
    }

    public boolean isBlacklisted(String jti) {
        return jti != null && Boolean.TRUE.equals(redis.hasKey(PREFIX + jti));
    }
}