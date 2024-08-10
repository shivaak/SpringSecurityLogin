package com.demo.userlogin.springsecuritylogin.controller;

import com.demo.userlogin.springsecuritylogin.config.JwtProperties;
import com.demo.userlogin.springsecuritylogin.dto.LoginRequest;
import com.demo.userlogin.springsecuritylogin.dto.LoginResponse;
import com.demo.userlogin.springsecuritylogin.dto.RefreshTokenResponse;
import com.demo.userlogin.springsecuritylogin.dto.StandardResponse;
import com.demo.userlogin.springsecuritylogin.security.JwtDecoder;
import com.demo.userlogin.springsecuritylogin.service.AuthService;
import com.demo.userlogin.springsecuritylogin.util.ResponseUtil;
import com.demo.userlogin.springsecuritylogin.util.helper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;
    private final JwtProperties jwtProperties;
    private final JwtDecoder jwtDecoder;

    @PostMapping("/login")
    public ResponseEntity<StandardResponse<LoginResponse>> login(@Valid  @RequestBody LoginRequest loginRequest){
        Map<String, Object> tokenMap = authService.login(loginRequest);
        String accessToken = (String) tokenMap.get("accessToken");
        String refreshToken = (String) tokenMap.get("refreshToken");
        int[] roles = (int[]) tokenMap.get("roles");
        log.info("User logged in successfully");
        // Set refresh token in HttpOnly cookie
        ResponseCookie cookie = ResponseCookie.from("refreshToken", refreshToken)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .sameSite("strict")
                .maxAge(Duration.ofMillis(jwtProperties.getRefreshTokenValidityInMs()))
                .build();

        //return  ResponseUtil.buildResponse(response, HttpStatus.OK);
        LoginResponse response = new LoginResponse(accessToken, roles);
        ResponseEntity<StandardResponse<LoginResponse>> responseEntity = ResponseUtil.buildResponse(response, HttpStatus.OK);
        return ResponseEntity.status(responseEntity.getStatusCode())
                .headers(responseEntity.getHeaders())
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(responseEntity.getBody());
    }

    @GetMapping("/refresh")
    public ResponseEntity<StandardResponse<RefreshTokenResponse>> refresh(HttpServletRequest request) {

        String refreshTokenFromCookie = helper.extractRefreshTokenFromCookie(request);
        if(refreshTokenFromCookie == null || refreshTokenFromCookie.isEmpty()) {
            throw new IllegalArgumentException("Refresh token not found");
        }

        RefreshTokenResponse refreshTokenResponse = authService.refresh(refreshTokenFromCookie);

        log.info("Token refreshed successfully");
        return ResponseUtil.buildResponse(refreshTokenResponse, HttpStatus.OK);
    }

    @PostMapping("/logout")
    public ResponseEntity<StandardResponse<String>> logout( HttpServletRequest request) {
        final String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new IllegalArgumentException("Authorization header is missing or invalid");
        }

        final String jwtToken = authHeader.substring(7);

        String refreshTokenFromCookie = helper.extractRefreshTokenFromCookie(request);
        authService.logout(jwtToken, refreshTokenFromCookie);

        // Invalidate the refresh token cookie
        ResponseCookie cookie = ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(0) // Setting maxAge to 0 to invalidate the cookie
                .build();
        log.info("Refresh token invalidated");

        log.info("User logged out successfully");

        ResponseEntity<StandardResponse<String>> responseEntity = ResponseUtil.buildResponse("Logout successful", HttpStatus.NO_CONTENT);

        return ResponseEntity.status(responseEntity.getStatusCode())
                .headers(responseEntity.getHeaders())
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(responseEntity.getBody());
    }
}
