package com.demo.userlogin.springsecuritylogin.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class RefreshTokenResponse {
    private String token;
    private int[] roles;
}