package com.demo.userlogin.springsecuritylogin.config;

import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

@Configuration
@RequiredArgsConstructor
public class CaffeineCacheConfig {

    private final JwtProperties jwtProperties;
    private final int BUFFER_TIME_IN_MS = 300000; // 5 minutes

    @Bean
    public com.github.benmanes.caffeine.cache.Cache<String, Boolean> accessTokenBlacklistCache() {
        return Caffeine.newBuilder()
                .expireAfterWrite(jwtProperties.getValidityInMs() + BUFFER_TIME_IN_MS, TimeUnit.MILLISECONDS)
                .build();
    }

    @Bean
    public com.github.benmanes.caffeine.cache.Cache<String, Boolean> refreshTokenBlacklistCache() {
        return Caffeine.newBuilder()
                .expireAfterWrite(jwtProperties.getRefreshTokenValidityInMs() + BUFFER_TIME_IN_MS, TimeUnit.MILLISECONDS)
                .build();
    }
}