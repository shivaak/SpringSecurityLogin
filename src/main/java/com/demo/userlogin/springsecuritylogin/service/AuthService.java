package com.demo.userlogin.springsecuritylogin.service;

import com.demo.userlogin.springsecuritylogin.audit.Audit;
import com.demo.userlogin.springsecuritylogin.dto.LoginRequest;
import com.demo.userlogin.springsecuritylogin.dto.LoginResponse;
import com.demo.userlogin.springsecuritylogin.security.JwtIssuer;
import com.demo.userlogin.springsecuritylogin.security.UserPrincipal;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtIssuer jwtIssuer;

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
        return LoginResponse.builder()
                .token(token)
                .build();
    }
}
