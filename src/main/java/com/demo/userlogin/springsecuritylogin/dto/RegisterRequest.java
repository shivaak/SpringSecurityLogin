package com.demo.userlogin.springsecuritylogin.dto;

import com.demo.userlogin.springsecuritylogin.audit.AuditableField;
import com.demo.userlogin.springsecuritylogin.model.Role;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {
    @AuditableField
    @NotBlank(message = "Username is mandatory")
    @Size(min = 4, max = 20, message = "Username must be between 4 and 20 characters")
    @Pattern(regexp = "^[a-zA-Z0-9]*$", message = "Username can only contain alphanumeric characters")
    private String username;

    @NotBlank(message = "Password is mandatory")
    @Size(min = 8, message = "Password must be at least 8 characters long")
    @Pattern(regexp = "^(?=.*[0-9])(?=.*[a-zA-Z]).*$", message = "Password must contain at least one letter and one number")
    private String password;

    @AuditableField
    @NotBlank(message = "FirstName is mandatory")
    private String firstName;

    @AuditableField
    private String LastName;

    @AuditableField
    private Role role;
}
