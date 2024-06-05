package com.demo.userlogin.springsecuritylogin.dto;

import lombok.*;

@Data
@AllArgsConstructor
@Builder
@Getter
@Setter
public class RefreshResponse {
    private String token;
}
