package com.demo.userlogin.springsecuritylogin.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Getter
@Setter
@Configuration
@ConfigurationProperties("security.jwt")
public class JwtProperties {
    /**
     * Secret key for the JWT token generation
     */
    private String secretKey;
    /**
     * Validity for the token in milliseconds
     */
    private long validityInMs;

    /**
     * Issuer for the JWT token
     */
    private String issuer;

    /**
     * Audience for the JWT token
     */
    private String audience;


    /**
     * Refresh token validity in milliseconds
     */
    private long refreshTokenValidityInMs;
}
