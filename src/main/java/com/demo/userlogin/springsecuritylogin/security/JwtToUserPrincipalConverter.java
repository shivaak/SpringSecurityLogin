package com.demo.userlogin.springsecuritylogin.security;

import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Component
@Slf4j
public class JwtToUserPrincipalConverter {

    public UserPrincipal convert(DecodedJWT jwt) {
        String username = jwt.getSubject();
        if (username == null) {
            log.error("JWT does not contain a subject");
            throw new IllegalArgumentException("JWT token is missing subject (username) claim");
        }

        List<SimpleGrantedAuthority> authorities = extractAuthoritiesFromClaim(jwt);
        if (authorities.isEmpty()) {
            log.warn("JWT token does not contain any roles");
        }

        return UserPrincipal.builder()
                .username(username)
                .authorities(authorities)
                .build();
    }

    private List<SimpleGrantedAuthority> extractAuthoritiesFromClaim(DecodedJWT jwt) {
        try {
            return jwt.getClaim("roles").asList(String.class)
                    .stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        } catch (Exception e) {
            log.error("Failed to extract authorities from JWT", e);
            return Collections.emptyList();
        }
    }
}
