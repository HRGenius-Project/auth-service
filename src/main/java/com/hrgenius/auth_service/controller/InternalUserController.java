package com.hrgenius.auth_service.controller;

import com.hrgenius.auth_service.dto.InternalCreateUserRequest;
import com.hrgenius.auth_service.dto.UserResponse;
import com.hrgenius.auth_service.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/internal/users")
@RequiredArgsConstructor
@Slf4j
public class InternalUserController {

    @Value("${internal.api-key:HRGeniusSecretKey2026}")
    private String internalApiKey;

    private final AuthService authService;

    @PostMapping
    public ResponseEntity<?> createInternalUser(
            @RequestHeader(value = "X-Internal-Key", required = false) String apiKey,
            @RequestBody InternalCreateUserRequest request) {

        log.info("Internal call received. Incoming X-Internal-Key: '{}' | Configured Key: '{}'", apiKey, internalApiKey);

        if (apiKey == null || !apiKey.trim().equals(internalApiKey.trim())) {
            log.warn("Forbidden access: API key mismatch or header missing!");
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Invalid or missing internal API key"));
        }

        UserResponse userResponse = authService.createInternalUser(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(userResponse);
    }
}