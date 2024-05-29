package com.demo.userlogin.springsecuritylogin.repository;

import com.demo.userlogin.springsecuritylogin.model.User;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    boolean existsByUsername(String username);

    // Find user by reset password token
    Optional<User> findByResetPasswordToken(String resetPasswordToken);

    // Delete user by username
    @Modifying
    @Transactional
    void deleteByUsername(String username);

    // Update user status (enabled/disabled)
    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.enabled = :enabled WHERE u.username = :username")
    void updateEnabledStatus(@Param("username") String username, @Param("enabled") boolean enabled);

    // Update user login attempts
    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.failedLoginAttempts = :failedLoginAttempts WHERE u.username = :username")
    void updateFailedLoginAttempts(@Param("username") String username, @Param("failedLoginAttempts") int failedLoginAttempts);

    // Update user lockout time
    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.lockoutTime = :lockoutTime WHERE u.username = :username")
    void updateLockoutTime(@Param("username") String username, @Param("lockoutTime") LocalDateTime lockoutTime);

    // Increment user login attempts
    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.failedLoginAttempts = u.failedLoginAttempts + 1 WHERE u.username = :username")
    void incrementFailedLoginAttempts(@Param("username") String username);

    // Reset user login attempts to 0
    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.failedLoginAttempts = 0 WHERE u.username = :username")
    void resetFailedLoginAttempts(@Param("username") String username);

    // Update user last login at
    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.lastLoginAt = :lastLoginAt WHERE u.username = :username")
    void updateLastLoginAt(@Param("username") String username, @Param("lastLoginAt") LocalDateTime lastLoginAt);

}
