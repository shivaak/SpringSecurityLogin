package com.demo.userlogin.springsecuritylogin.service;

import com.demo.userlogin.springsecuritylogin.audit.Audit;
import com.demo.userlogin.springsecuritylogin.audit.AuditableField;
import com.demo.userlogin.springsecuritylogin.dto.RegisterRequest;
import com.demo.userlogin.springsecuritylogin.dto.UpdateProfileRequest;
import com.demo.userlogin.springsecuritylogin.dto.UpdateUserRequest;
import com.demo.userlogin.springsecuritylogin.exception.UserAlreadyExistsException;
import com.demo.userlogin.springsecuritylogin.exception.UserNotFoundException;
import com.demo.userlogin.springsecuritylogin.model.User;
import com.demo.userlogin.springsecuritylogin.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    @Audit(action = "Register User")
    @Transactional
    public User register(RegisterRequest registerRequest) {
        if (userRepository.existsByUsername(registerRequest.getUsername())) {
            throw new UserAlreadyExistsException("User with username " + registerRequest.getUsername() + " already exists.");
        }
        validatePassword(registerRequest.getPassword());

        User user = User.builder()
                .username(registerRequest.getUsername())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .role(registerRequest.getRole())
                .firstName(registerRequest.getFirstName())
                .lastName(registerRequest.getLastName())
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .build();

        return userRepository.save(user);
    }

    @Audit(action = "Delete User")
    @Transactional
    public void deleteUserByUsername(String username) {
        userRepository.deleteByUsername(username);
    }

    @Audit(action = "Update UserProfile")
    @Transactional
    public void updateProfile(@AuditableField String username, UpdateProfileRequest updateProfileRequest) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found: " + username));

        user.setFirstName(updateProfileRequest.getFirstName());
        user.setLastName(updateProfileRequest.getLastName());

        userRepository.save(user);
    }

    @Audit(action = "Update UserAccount")
    @Transactional
    public void updateUser(@AuditableField String username, @AuditableField UpdateUserRequest updateUserRequest) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found: " + username));

        user.setRole(updateUserRequest.getRole());
        user.setEnabled(updateUserRequest.isEnabled());
        user.setAccountNonExpired(updateUserRequest.isAccountNonExpired());
        user.setAccountNonLocked(updateUserRequest.isAccountNonLocked());
        user.setCredentialsNonExpired(updateUserRequest.isCredentialsNonExpired());

        userRepository.save(user);
    }

    @Audit(action = "Disable User")
    @Transactional
    public void disableUser(@AuditableField  String username) {
        User user = getUserByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found: " + username));
        updateUserEnabledStatus(username, false);
    }

    @Audit(action = "Enable User")
    @Transactional
    public void enableUser(@AuditableField  String username) {
        User user = getUserByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found: " + username));
        updateUserEnabledStatus(username, true);
    }

    public Optional<User> getUserByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Transactional
    public void updateUserEnabledStatus(String username, boolean enabled) {
        userRepository.updateEnabledStatus(username, enabled);
    }

    @Transactional
    public void updateFailedLoginAttempts(String username, int failedLoginAttempts) {
        userRepository.updateFailedLoginAttempts(username, failedLoginAttempts);
    }

    @Transactional
    public void updateLockoutTime(String username, LocalDateTime lockoutTime) {
        userRepository.updateLockoutTime(username, lockoutTime);
    }

    @Transactional
    public void incrementFailedLoginAttempts(String username) {
        userRepository.incrementFailedLoginAttempts(username);
    }

    @Transactional
    public void resetFailedLoginAttempts(String username) {
        userRepository.resetFailedLoginAttempts(username);
    }

    @Transactional
    public void updateLastLoginAt(String username, LocalDateTime lastLoginAt) {
        userRepository.updateLastLoginAt(username, lastLoginAt);
    }

    @Audit(action = "Reset Password")
    @Transactional
    public void resetPassword(String username, String newPassword) {
        userRepository.findByUsername(username).ifPresent(user -> {
            user.setPassword(passwordEncoder.encode(newPassword));
            user.setResetPasswordToken(null);
            user.setResetPasswordTokenExpiry(null);
            userRepository.save(user);
        });
    }

    //Package-private method
    void validatePassword(String password) {
        if (password.length() < 8) {
            throw new IllegalArgumentException("Password must be at least 8 characters long");
        }
        if (!password.matches("^(?=.*[0-9])(?=.*[a-zA-Z]).*$")) {
            throw new IllegalArgumentException("Password must contain at least one letter and one number");
        }
    }

}
