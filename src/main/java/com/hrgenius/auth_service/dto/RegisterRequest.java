package com.hrgenius.auth_service.dto;

import jakarta.validation.constraints.*;
import java.util.Set;

public record RegisterRequest(
        @NotBlank @Size(min = 3, max = 50) String username,
        @NotBlank @Email String email,
        @NotBlank @Size(min = 8) String password,
        @NotEmpty Set<String> roles) {}