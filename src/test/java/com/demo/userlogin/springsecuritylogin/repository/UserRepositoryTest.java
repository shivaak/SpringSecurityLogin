package com.demo.userlogin.springsecuritylogin.repository;

import com.demo.userlogin.springsecuritylogin.model.Role;
import com.demo.userlogin.springsecuritylogin.model.User;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(SpringExtension.class)
@DataJpaTest
public class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    @PersistenceContext
    private EntityManager entityManager;

    private User user;

    @BeforeEach
    public void setUp() {
        // Clear the database to ensure clean state for each test
        userRepository.deleteAll();

        user = User.builder()
                .username("testuser")
                .password("password")
                .role(Role.ROLE_USER)
                .firstName("Test")
                .lastName("User")
                .createdAt(LocalDateTime.now())
                .build();
        userRepository.save(user);
    }

    @Test
    public void testFindByUsername() {
        Optional<User> foundUser = userRepository.findByUsername("testuser");
        assertThat(foundUser).isPresent();
        assertThat(foundUser.get().getUsername()).isEqualTo("testuser");
    }

    @Test
    public void testExistsByUsername() {
        boolean exists = userRepository.existsByUsername("testuser");
        assertThat(exists).isTrue();
    }

    @Test
    public void testDeleteByUsername() {
        userRepository.deleteByUsername("testuser");
        entityManager.flush();
        entityManager.clear();
        Optional<User> foundUser = userRepository.findByUsername("testuser");
        assertThat(foundUser).isNotPresent();
    }

    @Test
    public void testUpdateEnabledStatus() {
        userRepository.updateEnabledStatus("testuser", false);
        entityManager.flush();
        entityManager.clear();
        Optional<User> foundUser = userRepository.findByUsername("testuser");
        assertThat(foundUser).isPresent();
        assertThat(foundUser.get().isEnabled()).isFalse();
    }

    @Test
    public void testUpdateFailedLoginAttempts() {
        userRepository.updateFailedLoginAttempts("testuser", 5);
        entityManager.flush();
        entityManager.clear();
        Optional<User> foundUser = userRepository.findByUsername("testuser");
        assertThat(foundUser).isPresent();
        assertThat(foundUser.get().getFailedLoginAttempts()).isEqualTo(5);
    }

    @Test
    public void testUpdateLockoutTime() {
        LocalDateTime lockoutTime = LocalDateTime.now().plusHours(1);
        userRepository.updateLockoutTime("testuser", lockoutTime);
        entityManager.flush();
        entityManager.clear();
        Optional<User> foundUser = userRepository.findByUsername("testuser");
        assertThat(foundUser).isPresent();
        assertThat(foundUser.get().getLockoutTime()).isEqualTo(lockoutTime);
    }

    @Test
    @Transactional
    public void testIncrementFailedLoginAttempts() {
        userRepository.incrementFailedLoginAttempts("testuser");
        entityManager.flush();
        entityManager.clear();
        Optional<User> foundUser = userRepository.findByUsername("testuser");
        assertThat(foundUser).isPresent();
        assertThat(foundUser.get().getFailedLoginAttempts()).isEqualTo(1);
    }

    @Test
    @Transactional
    public void testResetFailedLoginAttempts() {
        userRepository.updateFailedLoginAttempts("testuser", 5);
        userRepository.resetFailedLoginAttempts("testuser");
        entityManager.flush();
        entityManager.clear();
        Optional<User> foundUser = userRepository.findByUsername("testuser");
        assertThat(foundUser).isPresent();
        assertThat(foundUser.get().getFailedLoginAttempts()).isEqualTo(0);
    }

    @Test
    public void testUpdateLastLoginAt() {
        LocalDateTime lastLoginAt = LocalDateTime.now();
        userRepository.updateLastLoginAt("testuser", lastLoginAt);
        entityManager.flush();
        entityManager.clear();
        Optional<User> foundUser = userRepository.findByUsername("testuser");
        assertThat(foundUser).isPresent();
        assertThat(foundUser.get().getLastLoginAt()).isEqualTo(lastLoginAt);
    }
}
