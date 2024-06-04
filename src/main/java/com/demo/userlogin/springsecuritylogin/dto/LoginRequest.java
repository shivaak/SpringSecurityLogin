package com.demo.userlogin.springsecuritylogin.dto;

import com.demo.userlogin.springsecuritylogin.audit.AuditableField;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class LoginRequest {
    @AuditableField
    @NotBlank
    private String username;
    @NotBlank
    private String password;
}
