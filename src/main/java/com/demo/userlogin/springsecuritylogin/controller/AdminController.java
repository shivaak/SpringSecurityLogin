package com.demo.userlogin.springsecuritylogin.controller;

import com.demo.userlogin.springsecuritylogin.security.UserPrincipal;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/admin")
@Slf4j
public class AdminController {
    @GetMapping("/hello")
    public String sayHelloToAdmin(@AuthenticationPrincipal UserPrincipal userPrincipal) {
        if (userPrincipal == null) {
            throw new IllegalStateException("User principal is missing");
        }
        log.info("saying hello to admin");
       // Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return "Heyyyyyyy, You are an Admin " + userPrincipal.getUsername() + "!";
    }
}
