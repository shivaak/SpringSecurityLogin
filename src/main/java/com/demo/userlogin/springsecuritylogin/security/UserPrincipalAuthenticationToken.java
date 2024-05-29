package com.demo.userlogin.springsecuritylogin.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.io.Serializable;

public class UserPrincipalAuthenticationToken extends AbstractAuthenticationToken implements Serializable {

    private final UserPrincipal principal;

    public UserPrincipalAuthenticationToken(
            UserPrincipal principal) {
        super(principal.getAuthorities());
        this.principal = principal;
        setAuthenticated(true); // This assumes the token is already authenticated.
    }

    @Override
    public Object getCredentials() {
        return null; // No credentials as it's a JWT-based authentication.
    }

    @Override
    public UserPrincipal getPrincipal() {
        return principal;
    }
}
