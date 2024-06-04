package com.demo.userlogin.springsecuritylogin.repository;

import com.demo.userlogin.springsecuritylogin.model.RefreshToken;
import com.demo.userlogin.springsecuritylogin.model.Role;
import com.demo.userlogin.springsecuritylogin.model.User;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(SpringExtension.class)
@DataJpaTest
public class RefreshTokenRepositoryTest {

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private UserRepository userRepository;

    @PersistenceContext
    private EntityManager entityManager;

    private User user;
    private RefreshToken refreshToken;

    @BeforeEach
    public void setUp() {
        // Clear the database to ensure a clean state for each test
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();

        // Create and save a user
        user = User.builder()
                .username("testuser")
                .password("password")
                .role(Role.ROLE_USER)
                .firstName("Test")
                .lastName("User")
                .createdAt(LocalDateTime.now())
                .build();
        userRepository.save(user);

        // Create and save a refresh token
        refreshToken = RefreshToken.builder()
                .token(generateSampleJwtToken())
                .user(user)
                .expiryDate(Instant.now().plusSeconds(3600))
                .build();
        refreshTokenRepository.save(refreshToken);
    }

    private String generateSampleJwtToken() {
        // For demonstration purposes, a static JWT token is returned
        // In a real scenario, you would generate a valid JWT token
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0dXNlciIsImlhdCI6MTUxNjIzOTAyMn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    }

    @Test
    public void testFindByToken() {
        Optional<RefreshToken> foundToken = refreshTokenRepository.findByToken(refreshToken.getToken());
        assertThat(foundToken).isPresent();
        assertThat(foundToken.get().getToken()).isEqualTo(refreshToken.getToken());
    }

    @Test
    public void testDeleteByToken() {
        refreshTokenRepository.deleteByToken(refreshToken.getToken());
        entityManager.flush();
        entityManager.clear();
        Optional<RefreshToken> foundToken = refreshTokenRepository.findByToken(refreshToken.getToken());
        assertThat(foundToken).isNotPresent();
    }
}
