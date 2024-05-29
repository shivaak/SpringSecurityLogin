package com.demo.userlogin.springsecuritylogin.controller;

import com.demo.userlogin.springsecuritylogin.dto.LoginRequest;
import com.demo.userlogin.springsecuritylogin.dto.LoginResponse;
import com.demo.userlogin.springsecuritylogin.dto.StandardResponse;
import com.demo.userlogin.springsecuritylogin.service.AuthService;
import com.demo.userlogin.springsecuritylogin.util.ResponseUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthController {

   private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<StandardResponse<LoginResponse>> login(@RequestBody LoginRequest loginRequest){
        LoginResponse response = authService.login(loginRequest);
        log.info("User logged in successfully");
        return  ResponseUtil.buildResponse(response, HttpStatus.OK);
    }
}
