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

    @Bean
    public com.github.benmanes.caffeine.cache.Cache<String, Boolean> accessTokenBlacklistCache() {
        return Caffeine.newBuilder()
                .expireAfterWrite(jwtProperties.getValidityInMs(), TimeUnit.MILLISECONDS)
                .build();
    }

    @Bean
    public com.github.benmanes.caffeine.cache.Cache<String, Boolean> refreshTokenBlacklistCache() {
        return Caffeine.newBuilder()
                .expireAfterWrite(jwtProperties.getRefreshTokenValidityInMs(), TimeUnit.MILLISECONDS)
                .build();
    }
}