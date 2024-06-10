package com.demo.userlogin.springsecuritylogin.integration_tests;

import com.demo.userlogin.springsecuritylogin.config.JwtProperties;
import com.demo.userlogin.springsecuritylogin.security.CustomUserDetailsService;
import com.demo.userlogin.springsecuritylogin.security.JwtAuthenticationFilter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
public class SecurityConfigurationTest {

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtProperties jwtProperties;

    @Test
    public void contextLoads() {
        assertThat(jwtAuthenticationFilter).isNotNull();
        assertThat(customUserDetailsService).isNotNull();
        assertThat(passwordEncoder).isNotNull();
        assertThat(jwtProperties).isNotNull();
    }
}
