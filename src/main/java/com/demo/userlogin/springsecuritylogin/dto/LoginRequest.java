package com.demo.userlogin.springsecuritylogin.dto;

import com.demo.userlogin.springsecuritylogin.audit.AuditableField;
import jakarta.validation.constraints.NotBlank;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class LoginRequest {
    @AuditableField
    @NotBlank
    private String username;
    @NotBlank
    private String password;
}
