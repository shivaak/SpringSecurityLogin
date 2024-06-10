package com.demo.userlogin.springsecuritylogin.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.demo.userlogin.springsecuritylogin.config.JwtProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtDecoder {

    private final JwtProperties jwtProperties;

    public DecodedJWT decode(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(jwtProperties.getSecretKey());
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(jwtProperties.getIssuer())
                    .withAudience(jwtProperties.getAudience())
                    .build();

            DecodedJWT decodedJWT = verifier.verify(token);

            // Manual expiry check. This check is not necessary as the library will throw an exception if the token is expired
            // I'm adding this check just to make the integration test pass
            Instant expiration = decodedJWT.getExpiresAt().toInstant();
            if (Instant.now().isAfter(expiration)) {
                throw new JWTVerificationException("Token is expired");
            }


            log.info("Token verified successfully for user: {}", decodedJWT.getSubject());
            return decodedJWT;
        } catch (JWTVerificationException e) {
            log.error("Token verification failed: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Internal error while decoding the token: {}", e.getMessage());
            throw e;
        }
    }
}
