package com.demo.userlogin.springsecuritylogin.dto;

import com.demo.userlogin.springsecuritylogin.model.Role;
import jakarta.validation.constraints.NotNull;
import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class UpdateUserRequest {
    @NotNull(message = "Role is mandatory")
    private Role role;

    @NotNull(message = "Enabled status is mandatory")
    private boolean enabled;

    @NotNull(message = "Account non-expired status is mandatory")
    private boolean accountNonExpired;

    @NotNull(message = "Account non-locked status is mandatory")
    private boolean accountNonLocked;

    @NotNull(message = "Credentials non-expired status is mandatory")
    private boolean credentialsNonExpired;
}