package com.demo.userlogin.springsecuritylogin.config;

import com.demo.userlogin.springsecuritylogin.security.JwtAuthenticationFilter;
import com.demo.userlogin.springsecuritylogin.security.JwtDecoder;
import com.demo.userlogin.springsecuritylogin.security.JwtToUserPrincipalConverter;
import com.github.benmanes.caffeine.cache.Cache;
import org.mockito.Mockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@Profile("test")
public class TestSecurityConfig {

    @MockBean(name = "accessTokenBlacklistCache")
    private Cache<String, Boolean> accessTokenBlacklistCache;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                        .requestMatchers("/api/v1/hello").hasRole("USER")
                        .anyRequest().permitAll());
        return http.build();
    }

    @Bean
    public JwtToUserPrincipalConverter jwtToUserPrincipalConverter() {
        return Mockito.mock(JwtToUserPrincipalConverter.class);
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return Mockito.mock(JwtDecoder.class);
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(jwtDecoder(), jwtToUserPrincipalConverter(), accessTokenBlacklistCache);
    }
}
