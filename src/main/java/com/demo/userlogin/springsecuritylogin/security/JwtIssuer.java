package com.demo.userlogin.springsecuritylogin.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtIssuer {

    private final JwtProperties jwtProperties;

    public String issueToken(UserPrincipal userPrincipal) {
        try {
            List<String> roles = userPrincipal.getAuthorities()
                    .stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());

            Instant now = Instant.now();
            Instant expiresAt = now.plus(Duration.ofMillis(jwtProperties.getValidityInMs()));

            return JWT.create()
                    .withSubject(userPrincipal.getUsername())
                    .withIssuedAt(now)
                    .withExpiresAt(expiresAt)
                    .withIssuer(jwtProperties.getIssuer())
                    .withAudience(jwtProperties.getAudience())
                    .withClaim("username", userPrincipal.getUsername())
                    .withClaim("roles", roles)
                    .sign(Algorithm.HMAC256(jwtProperties.getSecretKey()));
        } catch (Exception e) {
            log.error("Error issuing JWT token for user '{}'", userPrincipal.getUsername(), e);
            throw new RuntimeException("Error issuing JWT token", e);
        }
    }
}
