package com.demo.userlogin.springsecuritylogin.controller;

import com.demo.userlogin.springsecuritylogin.dto.*;
import com.demo.userlogin.springsecuritylogin.service.UserService;
import com.demo.userlogin.springsecuritylogin.util.ResponseUtil;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/users")
public class UserController {

    private final UserService userService;

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping(value="/register", consumes = "application/json")
    public ResponseEntity<StandardResponse<RegisterResponse>> register(@Valid @RequestBody RegisterRequest registerRequest) {
        return userService.register(registerRequest)
                .map(user -> {
                    log.info("User registered successfully");
                    RegisterResponse response = RegisterResponse.builder()
                            .username(user.getUsername())
                            .firstName(user.getFirstName())
                            .lastName(user.getLastName())
                            .role(user.getRole().name())
                            .build();
                    return ResponseUtil.buildResponse(response, "User registered successfully", HttpStatus.CREATED);
                }).orElseGet(() -> {
                    log.error("User registration failed");
                    return ResponseUtil.buildResponse(null, "User registration failed", HttpStatus.BAD_REQUEST);
                });
    }

    @PreAuthorize("hasRole('USER')")
    @PutMapping(value="/profile", consumes = "application/json")
    public ResponseEntity<StandardResponse<String>> updateProfile(Authentication authentication, @Valid @RequestBody UpdateProfileRequest updateProfileRequest) {
        String username = authentication.getName();
        return userService.updateProfile(username, updateProfileRequest)
                .map(user -> {
                    log.info("Profile updated successfully");
                    return ResponseUtil.buildResponse("Profile updated successfully", HttpStatus.OK);
                }).orElseGet(() -> {
                    log.error("Profile update failed");
                    return ResponseUtil.buildResponse("Profile update failed", HttpStatus.BAD_REQUEST);
                });
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping(value="/{username}", consumes = "application/json")
    public ResponseEntity<StandardResponse<String>> updateUser(@PathVariable String username, @Valid @RequestBody UpdateUserRequest updateUserRequest) {
        return userService.updateUser(username, updateUserRequest)
                .map(user -> {
                    log.info("User updated successfully");
                    return ResponseUtil.buildResponse("User updated successfully", HttpStatus.OK);
                }).orElseGet(() -> {
                    log.error("User update failed");
                    return ResponseUtil.buildResponse("User update failed", HttpStatus.BAD_REQUEST);
                });
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/{username}/disable")
    public ResponseEntity<StandardResponse<String>> disableUser(@PathVariable String username) {
        return userService.getUserByUsername(username)
                .map(user -> {
                    userService.updateUserEnabledStatus(username, false);
                    log.info("User disabled successfully");
                    return ResponseUtil.buildResponse("User disabled successfully", HttpStatus.OK);
                }).orElseGet(() -> {
                    log.error("User not found");
                    return ResponseUtil.buildResponse(null, "User not found",HttpStatus.NOT_FOUND, false);
                });
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/{username}/enable")
    public ResponseEntity<StandardResponse<String>> enableUser(@PathVariable String username) {
        return userService.getUserByUsername(username)
                .map(user -> {
                    userService.updateUserEnabledStatus(username, true);
                    log.info("User enabled successfully");
                    return ResponseUtil.buildResponse("User enabled successfully", HttpStatus.OK);
                }).orElseGet(() -> {
                    log.error("User not found");
                    return ResponseUtil.buildResponse(null, "User not found", HttpStatus.NOT_FOUND, false);
                });
    }
}