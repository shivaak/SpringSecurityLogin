package com.demo.userlogin.springsecuritylogin.config;

import com.demo.userlogin.springsecuritylogin.model.Role;
import com.demo.userlogin.springsecuritylogin.model.User;
import com.demo.userlogin.springsecuritylogin.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class DataInitializer {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserConfigProperties userConfigProperties;

    @PostConstruct
    public void init() {
        if (userRepository.count() == 0) {
            log.info("No users found in the database. Creating initial users.");

            // Create admin users
            if(userConfigProperties.getAdmins() != null) {
                userConfigProperties.getAdmins().forEach(this::createAdminUser);
            }

            // Create regular users
            if(userConfigProperties.getRegulars() != null) {
                userConfigProperties.getRegulars().forEach(this::createRegularUser);
            }

            log.info("Initial users created successfully.");
        } else {
            log.info("Users found in the database. Skipping user creation.");
        }
    }

    private void createAdminUser(UserConfigProperties.UserConfig userConfig) {
        createUser(userConfig, Role.ROLE_ADMIN);
    }

    private void createRegularUser(UserConfigProperties.UserConfig userConfig) {
        createUser(userConfig, Role.ROLE_USER);
    }

    private void createUser(UserConfigProperties.UserConfig userConfig, Role role) {
        User user = User.builder()
                .username(userConfig.getUsername())
                .password(passwordEncoder.encode(userConfig.getPassword()))
                .firstName(userConfig.getFirstName())
                .lastName(userConfig.getLastName())
                .role(role)
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .build();
        userRepository.save(user);
    }
}
