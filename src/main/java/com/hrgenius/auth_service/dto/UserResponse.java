package com.hrgenius.auth_service.dto;

import java.util.Set;

public record UserResponse(
        Long id,
        String username,
        String email,
        boolean enabled,
        Set<String> roles
) {}