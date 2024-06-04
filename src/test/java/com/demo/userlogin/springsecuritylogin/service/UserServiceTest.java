package com.demo.userlogin.springsecuritylogin.service;

import com.demo.userlogin.springsecuritylogin.dto.RegisterRequest;
import com.demo.userlogin.springsecuritylogin.dto.UpdateProfileRequest;
import com.demo.userlogin.springsecuritylogin.dto.UpdateUserRequest;
import com.demo.userlogin.springsecuritylogin.exception.UserAlreadyExistsException;
import com.demo.userlogin.springsecuritylogin.model.Role;
import com.demo.userlogin.springsecuritylogin.model.User;
import com.demo.userlogin.springsecuritylogin.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private UserService userService;

    private User user;

    @BeforeEach
    public void setUp() {
        user = User.builder()
                .username("testuser")
                .password("encodedPassword")
                .role(Role.ROLE_USER)
                .firstName("Test")
                .lastName("User")
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .createdAt(LocalDateTime.now())
                .build();
    }

    @Test
    public void testRegisterUser_Success() {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setUsername("testuser");
        registerRequest.setPassword("password1");
        registerRequest.setRole(Role.ROLE_USER);
        registerRequest.setFirstName("Test");
        registerRequest.setLastName("User");

        when(userRepository.existsByUsername("testuser")).thenReturn(false);
        when(passwordEncoder.encode("password1")).thenReturn("encodedPassword");
        when(userRepository.save(any(User.class))).thenReturn(user);

        Optional<User> registeredUser = userService.register(registerRequest);

        assertThat(registeredUser).isPresent();
        assertThat(registeredUser.get().getUsername()).isEqualTo("testuser");
        verify(userRepository).existsByUsername("testuser");
        verify(passwordEncoder).encode("password1");
        verify(userRepository).save(any(User.class));
    }

    @Test
    public void testRegisterUser_UserAlreadyExists() {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setUsername("testuser");

        when(userRepository.existsByUsername("testuser")).thenReturn(true);

        assertThrows(UserAlreadyExistsException.class, () -> userService.register(registerRequest));

        verify(userRepository).existsByUsername("testuser");
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    public void testGetUserByUsername() {
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));

        Optional<User> foundUser = userService.getUserByUsername("testuser");

        assertThat(foundUser).isPresent();
        assertThat(foundUser.get().getUsername()).isEqualTo("testuser");
        verify(userRepository).findByUsername("testuser");
    }

    @Test
    public void testDeleteUserByUsername() {
        doNothing().when(userRepository).deleteByUsername("testuser");

        userService.deleteUserByUsername("testuser");

        verify(userRepository).deleteByUsername("testuser");
    }

    @Test
    public void testUpdateProfile() {
        UpdateProfileRequest updateProfileRequest = new UpdateProfileRequest();
        updateProfileRequest.setFirstName("NewFirstName");
        updateProfileRequest.setLastName("NewLastName");

        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenReturn(user);

        Optional<User> updatedUser = userService.updateProfile("testuser", updateProfileRequest);

        assertThat(updatedUser).isPresent();
        assertThat(updatedUser.get().getFirstName()).isEqualTo("NewFirstName");
        assertThat(updatedUser.get().getLastName()).isEqualTo("NewLastName");
        verify(userRepository).findByUsername("testuser");
        verify(userRepository).save(any(User.class));
    }

    @Test
    public void testUpdateUser() {
        UpdateUserRequest updateUserRequest = new UpdateUserRequest();
        updateUserRequest.setRole(Role.ROLE_ADMIN);
        updateUserRequest.setEnabled(false);
        updateUserRequest.setAccountNonExpired(false);
        updateUserRequest.setAccountNonLocked(false);
        updateUserRequest.setCredentialsNonExpired(false);

        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenReturn(user);

        Optional<User> updatedUser = userService.updateUser("testuser", updateUserRequest);

        assertThat(updatedUser).isPresent();
        assertThat(updatedUser.get().getRole()).isEqualTo(Role.ROLE_ADMIN);
        assertThat(updatedUser.get().isEnabled()).isFalse();
        assertThat(updatedUser.get().isAccountNonExpired()).isFalse();
        assertThat(updatedUser.get().isAccountNonLocked()).isFalse();
        assertThat(updatedUser.get().isCredentialsNonExpired()).isFalse();
        verify(userRepository).findByUsername("testuser");
        verify(userRepository).save(any(User.class));
    }

    @Test
    public void testUpdateUserEnabledStatus() {
        doNothing().when(userRepository).updateEnabledStatus("testuser", false);

        userService.updateUserEnabledStatus("testuser", false);

        verify(userRepository).updateEnabledStatus("testuser", false);
    }

    @Test
    public void testUpdateFailedLoginAttempts() {
        doNothing().when(userRepository).updateFailedLoginAttempts("testuser", 5);

        userService.updateFailedLoginAttempts("testuser", 5);

        verify(userRepository).updateFailedLoginAttempts("testuser", 5);
    }

    @Test
    public void testUpdateLockoutTime() {
        LocalDateTime lockoutTime = LocalDateTime.now().plusHours(1);
        doNothing().when(userRepository).updateLockoutTime("testuser", lockoutTime);

        userService.updateLockoutTime("testuser", lockoutTime);

        verify(userRepository).updateLockoutTime("testuser", lockoutTime);
    }

    @Test
    public void testIncrementFailedLoginAttempts() {
        doNothing().when(userRepository).incrementFailedLoginAttempts("testuser");

        userService.incrementFailedLoginAttempts("testuser");

        verify(userRepository).incrementFailedLoginAttempts("testuser");
    }

    @Test
    public void testResetFailedLoginAttempts() {
        doNothing().when(userRepository).resetFailedLoginAttempts("testuser");

        userService.resetFailedLoginAttempts("testuser");

        verify(userRepository).resetFailedLoginAttempts("testuser");
    }

    @Test
    public void testUpdateLastLoginAt() {
        LocalDateTime lastLoginAt = LocalDateTime.now();
        doNothing().when(userRepository).updateLastLoginAt("testuser", lastLoginAt);

        userService.updateLastLoginAt("testuser", lastLoginAt);

        verify(userRepository).updateLastLoginAt("testuser", lastLoginAt);
    }

    @Test
    public void testResetPassword() {
        String newPassword = "newPassword1";
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
        when(passwordEncoder.encode(newPassword)).thenReturn("encodedNewPassword");
        when(userRepository.save(any(User.class))).thenReturn(user);

        userService.resetPassword("testuser", newPassword);

        assertThat(user.getPassword()).isEqualTo("encodedNewPassword");
        assertThat(user.getResetPasswordToken()).isNull();
        assertThat(user.getResetPasswordTokenExpiry()).isNull();
        verify(userRepository).findByUsername("testuser");
        verify(passwordEncoder).encode(newPassword);
        verify(userRepository).save(any(User.class));
    }

    @Test
    public void testValidatePassword_Success() {
        // Assuming this method has package-private access in UserService
        String validPassword = "password1";
        userService.validatePassword(validPassword);
        // If no exception is thrown, the password is valid
    }

    @Test
    public void testValidatePassword_TooShort() {
        String shortPassword = "short";
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            userService.validatePassword(shortPassword);
        });
        assertThat(exception.getMessage()).isEqualTo("Password must be at least 8 characters long");
    }

    @Test
    public void testValidatePassword_NoNumber() {
        String noNumberPassword = "password";
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            userService.validatePassword(noNumberPassword);
        });
        assertThat(exception.getMessage()).isEqualTo("Password must contain at least one letter and one number");
    }

    @Test
    public void testValidatePassword_NoLetter() {
        String noLetterPassword = "12345678";
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            userService.validatePassword(noLetterPassword);
        });
        assertThat(exception.getMessage()).isEqualTo("Password must contain at least one letter and one number");
    }
}
