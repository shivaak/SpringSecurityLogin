package com.demo.userlogin.springsecuritylogin.security.listener;

import com.demo.userlogin.springsecuritylogin.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuthenticationFailureEventListener {

    private final UserService userService;

    @EventListener
    public void onAuthenticationFailure(AuthenticationFailureBadCredentialsEvent event) {
        Object principal = event.getAuthentication().getPrincipal();

        if (principal instanceof String username) {
            userService.incrementFailedLoginAttempts(username);
            log.info("Incremented failed login attempts for user {}", username);
        }
    }
}