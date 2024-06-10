package com.demo.userlogin.springsecuritylogin.controller;

import com.demo.userlogin.springsecuritylogin.dto.*;
import com.demo.userlogin.springsecuritylogin.model.User;
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
        User user = userService.register(registerRequest);
        log.info("User registered successfully: {}", user.getUsername());
        RegisterResponse response = RegisterResponse.builder()
                .username(user.getUsername())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .role(user.getRole().name())
                .build();
        return ResponseUtil.buildResponse(response, "User registered successfully", HttpStatus.CREATED);
    }


    @PreAuthorize("hasRole('USER')")
    @PutMapping(value="/profile", consumes = "application/json")
    public ResponseEntity<StandardResponse<String>> updateProfile(Authentication authentication, @Valid @RequestBody UpdateProfileRequest updateProfileRequest) {
        String username = authentication.getName();
        userService.updateProfile(username, updateProfileRequest);
        log.info("Profile updated successfully for user: {}", username);
        return ResponseUtil.buildResponse("Profile updated successfully", HttpStatus.OK);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping(value="/{username}", consumes = "application/json")
    public ResponseEntity<StandardResponse<String>> updateUser(@PathVariable String username, @Valid @RequestBody UpdateUserRequest updateUserRequest) {
        userService.updateUser(username, updateUserRequest);
        log.info("User updated successfully: {}", username);
        return ResponseUtil.buildResponse("User updated successfully", HttpStatus.OK);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/{username}/disable")
    public ResponseEntity<StandardResponse<String>> disableUser(@PathVariable String username) {
        userService.disableUser(username);
        log.info("User disabled successfully: {}", username);
        return ResponseUtil.buildResponse("User disabled successfully", HttpStatus.OK);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/{username}/enable")
    public ResponseEntity<StandardResponse<String>> enableUser(@PathVariable String username) {
        userService.enableUser(username);
        log.info("User enabled successfully: {}", username);
        return ResponseUtil.buildResponse("User enabled successfully", HttpStatus.OK);
    }
}