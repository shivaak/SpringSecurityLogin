package com.demo.userlogin.springsecuritylogin.config;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;


// Class used to map the user configuration properties from the application.properties file
@Getter
@Setter
@Configuration
@ConfigurationProperties("users")
public class UserConfigProperties {
    private List<UserConfig> admins;
    private List<UserConfig> regulars;

    @Data
    public static class UserConfig {
        private String username;
        private String password;
        private String firstName;
        private String lastName;
    }
}