package com.hrgenius.auth_service.dto;

public record TokenResponse(String accessToken, String refreshToken, String tokenType,
                            long expiresInSeconds, boolean mustChangePassword) {}