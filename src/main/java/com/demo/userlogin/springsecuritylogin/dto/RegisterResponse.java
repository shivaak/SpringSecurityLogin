package com.demo.userlogin.springsecuritylogin.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class RegisterResponse {
    private String username;
    private String firstName;
    private String lastName;
    private String role;
}
