package com.demo.userlogin.springsecuritylogin.security.listener;

import com.demo.userlogin.springsecuritylogin.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuthenticationSuccessEventListener {

    private final UserService userService;

    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        Object principal = event.getAuthentication().getPrincipal();

        if (principal instanceof UserDetails) {
            String username = ((UserDetails) principal).getUsername();
            LocalDateTime now = LocalDateTime.now();
            userService.updateLastLoginAt(username, now);
            userService.resetFailedLoginAttempts(username); // Reset failed login attempts on success
            log.info("Updated last login time and reset failed login attempts for user {}", username);
        }
    }
}