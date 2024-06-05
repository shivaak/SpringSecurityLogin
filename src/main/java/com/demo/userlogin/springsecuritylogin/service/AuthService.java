package com.demo.userlogin.springsecuritylogin.service;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.demo.userlogin.springsecuritylogin.audit.Audit;
import com.demo.userlogin.springsecuritylogin.config.JwtProperties;
import com.demo.userlogin.springsecuritylogin.dto.LoginRequest;
import com.demo.userlogin.springsecuritylogin.dto.LoginResponse;
import com.demo.userlogin.springsecuritylogin.dto.RefreshResponse;
import com.demo.userlogin.springsecuritylogin.model.RefreshToken;
import com.demo.userlogin.springsecuritylogin.model.User;
import com.demo.userlogin.springsecuritylogin.repository.RefreshTokenRepository;
import com.demo.userlogin.springsecuritylogin.repository.UserRepository;
import com.demo.userlogin.springsecuritylogin.security.JwtDecoder;
import com.demo.userlogin.springsecuritylogin.security.JwtIssuer;
import com.demo.userlogin.springsecuritylogin.security.JwtToUserPrincipalConverter;
import com.demo.userlogin.springsecuritylogin.security.UserPrincipal;
import com.github.benmanes.caffeine.cache.Cache;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtIssuer jwtIssuer;
    private final JwtDecoder jwtDecoder;
    private final JwtToUserPrincipalConverter jwtToUserPrincipalConverter;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtProperties jwtProperties;
    private final Cache<String, Boolean> accessTokenBlacklistCache;
    private final Cache<String, Boolean> refreshTokenBlacklistCache;

    @Audit(action = "Login", logPoint = Audit.LogPoint.AFTER)
    public LoginResponse login(LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        String token = jwtIssuer.issueToken(userPrincipal);
        String refreshToken = jwtIssuer.issueRefreshToken(userPrincipal);

        saveRefreshToken(userPrincipal.getUsername(), refreshToken);

        return LoginResponse.builder()
                .token(token)
                .refreshToken(refreshToken)
                .build();
    }

    @Audit(action = "Refresh Token", logPoint = Audit.LogPoint.AFTER)
    @Transactional
    public RefreshResponse refresh(String refreshToken) {
        DecodedJWT decodedJWT = jwtDecoder.decode(refreshToken);

        // Ensure the token is a refresh token
        if (!"refresh".equals(decodedJWT.getClaim("type").asString())) {
            throw new JWTVerificationException("Invalid token for refresh");
        }

        // Validate the refresh token
        validateStoredRefreshToken(refreshToken);

        UserPrincipal userPrincipal = jwtToUserPrincipalConverter.convert(decodedJWT);
        String token = jwtIssuer.issueToken(userPrincipal);

        return RefreshResponse.builder()
                .token(token)
                .build();
    }

    @Audit(action = "Logout", logPoint = Audit.LogPoint.AFTER)
    @Transactional
    public void logout(String accessToken, String refreshToken) {
        DecodedJWT decodedAccessToken = jwtDecoder.decode(accessToken);
        DecodedJWT decodedRefreshToken = jwtDecoder.decode(refreshToken);

        // Ensure the tokens are of correct types
        if (!"access".equals(decodedAccessToken.getClaim("type").asString())) {
            throw new JWTVerificationException("Invalid access token type for logout");
        }
        if (!"refresh".equals(decodedRefreshToken.getClaim("type").asString())) {
            throw new JWTVerificationException("Invalid refresh token type for logout");
        }

        // Ensure the tokens belong to the same user
        String accessTokenSubject = decodedAccessToken.getSubject();
        String refreshTokenSubject = decodedRefreshToken.getSubject();
        if (!accessTokenSubject.equals(refreshTokenSubject)) {
            throw new JWTVerificationException("Access token and refresh token do not belong to the same user");
        }

        // Blacklist the access token and refresh token
        blacklistAccessToken(accessToken);
        blacklistRefreshToken(refreshToken);

        // Delete the refresh token from the database
        refreshTokenRepository.deleteByToken(refreshToken);
    }

    private void blacklistAccessToken(String token) {
        accessTokenBlacklistCache.put(token, Boolean.TRUE);
    }

    private void blacklistRefreshToken(String token) {
        refreshTokenBlacklistCache.put(token, Boolean.TRUE);
    }

    private void saveRefreshToken(String username, String refreshToken) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        RefreshToken token = RefreshToken.builder()
                .token(refreshToken)
                .user(user)
                .expiryDate(Instant.now().plusMillis(jwtProperties.getRefreshTokenValidityInMs()))
                .build();

        refreshTokenRepository.save(token);
    }

    private void validateStoredRefreshToken(String refreshToken) {
        RefreshToken token = refreshTokenRepository.findByToken(refreshToken)
                .orElseThrow(() -> new JWTVerificationException("Invalid refresh token"));

        if (token.getExpiryDate().isBefore(Instant.now())) {
            // Delete the refresh token from the database
            refreshTokenRepository.deleteByToken(refreshToken);
            throw new JWTVerificationException("Refresh token expired");
        }

        if (refreshTokenBlacklistCache.getIfPresent(refreshToken) != null) {
            throw new JWTVerificationException("Refresh token has been blacklisted");
        }
    }

    private void invalidateOldRefreshToken(String refreshToken) {
        refreshTokenRepository.deleteByToken(refreshToken);
    }
}
