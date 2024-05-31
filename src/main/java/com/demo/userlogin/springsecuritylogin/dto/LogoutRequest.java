package com.demo.userlogin.springsecuritylogin.dto;

import lombok.Data;

@Data
public class LogoutRequest {
    private String refreshToken;
}