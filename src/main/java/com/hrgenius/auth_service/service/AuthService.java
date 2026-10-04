package com.hrgenius.auth_service.service;

import com.hrgenius.auth_service.dto.*;
import com.hrgenius.auth_service.entity.Role;
import com.hrgenius.auth_service.entity.User;
import com.hrgenius.auth_service.repository.RoleRepository;
import com.hrgenius.auth_service.repository.UserRepository;
import com.hrgenius.auth_service.security.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final TokenBlacklistService tokenBlacklistService;

    public TokenResponse login(LoginRequest request) {
        User user = userRepository.findByUsername(request.username())
                .filter(User::isEnabled)
                .filter(u -> passwordEncoder.matches(request.password(), u.getPasswordHash()))
                .orElseThrow(() -> new BadCredentialsException("Invalid username or password"));
        return issueTokens(user);
    }

    public TokenResponse refresh(String refreshToken) {
        Long userId = refreshTokenService.validate(refreshToken)
                .orElseThrow(() -> new BadCredentialsException("Invalid or expired refresh token"));
        User user = userRepository.findById(userId)
                .filter(User::isEnabled)
                .orElseThrow(() -> new BadCredentialsException("User not found or disabled"));
        refreshTokenService.delete(refreshToken);
        return issueTokens(user);
    }

    public void logout(String refreshToken, String authHeader) {
        refreshTokenService.delete(refreshToken);
        blacklistAccessToken(authHeader);
    }

    @Transactional
    public UserResponse register(RegisterRequest request) {
        return createUser(request.username(), request.email(), request.password(), request.roles(), false);
    }

    @Transactional
    public UserResponse createInternalUser(InternalCreateUserRequest request) {
        return createUser(request.username(), request.email(), request.temporaryPassword(), request.roles(), true);
    }

    @Transactional
    public void deleteUser(String username) {
        userRepository.findByUsername(username).ifPresent(userRepository::delete);
    }

    @Transactional
    public TokenResponse changePassword(String username, ChangePasswordRequest request, String authHeader) {
        User user = userRepository.findByUsername(username)
                .filter(User::isEnabled)
                .orElseThrow(() -> new BadCredentialsException("User not found or disabled"));
        if (!passwordEncoder.matches(request.currentPassword(), user.getPasswordHash())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Current password is incorrect");
        }
        if (request.currentPassword().equals(request.newPassword())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "New password must be different");
        }
        user.setPasswordHash(passwordEncoder.encode(request.newPassword()));
        user.setMustChangePassword(false);
        userRepository.save(user);
        blacklistAccessToken(authHeader);
        return issueTokens(user);
    }

    private UserResponse createUser(String username, String email, String rawPassword,
                                    Set<String> roleNames, boolean mustChangePassword) {
        if (userRepository.existsByUsername(username)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Username already exists");
        }
        if (userRepository.existsByEmail(email)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists");
        }
        Set<Role> roles = new HashSet<>();
        for (String name : roleNames) {
            Role role = roleRepository.findByName(name.toUpperCase())
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown role: " + name));
            roles.add(role);
        }
        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPasswordHash(passwordEncoder.encode(rawPassword));
        user.setRoles(roles);
        user.setMustChangePassword(mustChangePassword);
        User saved = userRepository.save(user);
        return new UserResponse(saved.getId(), saved.getUsername(), saved.getEmail(),
                saved.getRoles().stream().map(Role::getName).collect(Collectors.toSet()));
    }

    private void blacklistAccessToken(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            try {
                Claims claims = jwtService.parse(authHeader.substring(7));
                Duration ttl = Duration.between(Instant.now(), claims.getExpiration().toInstant());
                tokenBlacklistService.blacklist(claims.getId(), ttl);
            } catch (JwtException | IllegalArgumentException e) {
                // token pehle se invalid hai
            }
        }
    }

    private TokenResponse issueTokens(User user) {
        String access = jwtService.generateAccessToken(user);
        String refresh = refreshTokenService.create(user.getId());
        return new TokenResponse(access, refresh, "Bearer",
                jwtService.getAccessExpirySeconds(), user.isMustChangePassword());
    }
}