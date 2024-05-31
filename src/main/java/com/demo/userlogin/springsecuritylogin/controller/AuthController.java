package com.demo.userlogin.springsecuritylogin.controller;

import com.demo.userlogin.springsecuritylogin.dto.*;
import com.demo.userlogin.springsecuritylogin.service.AuthService;
import com.demo.userlogin.springsecuritylogin.util.ResponseUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthController {

   private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<StandardResponse<LoginResponse>> login(@RequestBody LoginRequest loginRequest){
        LoginResponse response = authService.login(loginRequest);
        log.info("User logged in successfully");
        return  ResponseUtil.buildResponse(response, HttpStatus.OK);
    }

    @PostMapping("/refresh")
    public ResponseEntity<StandardResponse<RefreshTokenResponse>> refresh(@RequestBody RefreshTokenRequest refreshTokenRequest) {
        LoginResponse response = authService.refresh(refreshTokenRequest.getRefreshToken());
        RefreshTokenResponse refreshTokenResponse = RefreshTokenResponse.builder()
                .token(response.getToken())
                .refreshToken(response.getRefreshToken())
                .build();
        log.info("Token refreshed successfully");
        return ResponseUtil.buildResponse(refreshTokenResponse, HttpStatus.OK);
    }

    @PostMapping("/logout")
    public ResponseEntity<StandardResponse<Void>> logout(@RequestBody LogoutRequest logoutRequest) {
        authService.logout(logoutRequest.getRefreshToken());
        log.info("User logged out successfully");
        return ResponseUtil.buildResponse(null, HttpStatus.OK);
    }
}
