package com.demo.userlogin.springsecuritylogin.service;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.demo.userlogin.springsecuritylogin.audit.Audit;
import com.demo.userlogin.springsecuritylogin.dto.LoginRequest;
import com.demo.userlogin.springsecuritylogin.dto.LoginResponse;
import com.demo.userlogin.springsecuritylogin.model.RefreshToken;
import com.demo.userlogin.springsecuritylogin.model.User;
import com.demo.userlogin.springsecuritylogin.repository.RefreshTokenRepository;
import com.demo.userlogin.springsecuritylogin.repository.UserRepository;
import com.demo.userlogin.springsecuritylogin.security.*;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtIssuer jwtIssuer;
    private final JwtDecoder jwtDecoder;
    private final JwtToUserPrincipalConverter jwtToUserPrincipalConverter;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtProperties jwtProperties;


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
    public LoginResponse refresh(String refreshToken) {
        DecodedJWT decodedJWT = jwtDecoder.decode(refreshToken);
        // Ensure the token is a refresh token
        if (!"refresh".equals(decodedJWT.getClaim("type").asString())) {
            throw new JWTVerificationException("Invalid token for refresh");
        }

        // Validate the refresh token
        validateStoredRefreshToken(refreshToken);

        UserPrincipal userPrincipal = jwtToUserPrincipalConverter.convert(decodedJWT);

        String token = jwtIssuer.issueToken(userPrincipal);
        String newRefreshToken = jwtIssuer.issueRefreshToken(userPrincipal);

        // Invalidate the old refresh token
        invalidateOldRefreshToken(refreshToken);

        // Save the new refresh token
        saveRefreshToken(userPrincipal.getUsername(), newRefreshToken);;

        return LoginResponse.builder()
                .token(token)
                .refreshToken(newRefreshToken)
                .build();
    }

    @Audit(action = "Logout", logPoint = Audit.LogPoint.AFTER)
    @Transactional
    public void logout(String refreshToken) {
        DecodedJWT decodedJWT = jwtDecoder.decode(refreshToken);

        // Ensure the token is a refresh token
        if (!"refresh".equals(decodedJWT.getClaim("type").asString())) {
            throw new JWTVerificationException("Invalid token type for logout");
        }

        // Delete the refresh token from the database
        refreshTokenRepository.deleteByToken(refreshToken);
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

    private void invalidateOldRefreshToken(String refreshToken) {
        refreshTokenRepository.deleteByToken(refreshToken);
    }

    private void validateStoredRefreshToken(String refreshToken) {
        RefreshToken token = refreshTokenRepository.findByToken(refreshToken)
                .orElseThrow(() -> new JWTVerificationException("Invalid refresh token"));

        if (token.getExpiryDate().isBefore(Instant.now())) {
            throw new JWTVerificationException("Refresh token expired");
        }
    }
}
