package com.demo.userlogin.springsecuritylogin.controller;

import com.demo.userlogin.springsecuritylogin.config.TestSecurityConfig;
import com.demo.userlogin.springsecuritylogin.dto.RegisterRequest;
import com.demo.userlogin.springsecuritylogin.dto.UpdateProfileRequest;
import com.demo.userlogin.springsecuritylogin.dto.UpdateUserRequest;
import com.demo.userlogin.springsecuritylogin.exception.UserAlreadyExistsException;
import com.demo.userlogin.springsecuritylogin.model.Role;
import com.demo.userlogin.springsecuritylogin.model.User;
import com.demo.userlogin.springsecuritylogin.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.util.Optional;

import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(UserController.class)
@Import(TestSecurityConfig.class)
@ActiveProfiles("test")
public class UserControllerTest implements AutoCloseable {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserService userService;

    @Autowired
    private ObjectMapper objectMapper;

    private AutoCloseable mocks;

    @BeforeEach
    public void setUp() {
        mocks = MockitoAnnotations.openMocks(this);
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    public void testRegister_Success() throws Exception {
        RegisterRequest registerRequest = createValidRegisterRequest();
        User user = createUser("newuser", Role.ROLE_USER);

        when(userService.register(any(RegisterRequest.class))).thenReturn(Optional.of(user));

        performPostSuccess(registerRequest)
                .andExpect(jsonPath("$.message", equalTo("User registered successfully")))
                .andExpect(jsonPath("$.data.username", equalTo("newuser")));

        verify(userService, times(1)).register(any(RegisterRequest.class));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    public void testRegister_InvalidUsername() throws Exception {
        RegisterRequest registerRequest = createRegisterRequest("nu", "password123");

        performPostBadRequest(registerRequest);
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    public void testRegister_InvalidPassword() throws Exception {
        RegisterRequest registerRequest = createRegisterRequest("newuser", "pwd");

        performPostBadRequest(registerRequest);
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    public void testRegister_MissingFields() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest();

        performPostBadRequest(registerRequest);
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    public void testRegister_ExistingUsername() throws Exception {
        RegisterRequest registerRequest = createValidRegisterRequest();
        when(userService.register(any(RegisterRequest.class))).thenThrow(new UserAlreadyExistsException("User with username " + registerRequest.getUsername() + " already exists."));

        performPutConflictRequest(registerRequest);

        verify(userService, times(1)).register(any(RegisterRequest.class));
    }

    @Test
    @WithMockUser(roles = "USER")
    public void testUpdateProfile_Success() throws Exception {
        UpdateProfileRequest updateProfileRequest = new UpdateProfileRequest("First", "Last");
        User user = createUser("testuser", Role.ROLE_USER);

        when(userService.updateProfile(anyString(), any(UpdateProfileRequest.class))).thenReturn(Optional.of(user));

        performPutSuccess("/api/v1/users/profile", updateProfileRequest)
                .andExpect(jsonPath("$.data", equalTo("Profile updated successfully")))
                .andExpect(jsonPath("$.message", equalTo("Request was successful")));

        verify(userService, times(1)).updateProfile(anyString(), any(UpdateProfileRequest.class));
    }

    @Test
    @WithMockUser(roles = "USER")
    public void testUpdateProfile_MissingFields() throws Exception {
        UpdateProfileRequest updateProfileRequest = new UpdateProfileRequest();

        performPutBadRequest("/api/v1/users/profile", updateProfileRequest);
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    public void testUpdateUser_Success() throws Exception {
        UpdateUserRequest updateUserRequest = new UpdateUserRequest(Role.ROLE_ADMIN, true, true, true, true);
        User user = createUser("testuser", Role.ROLE_ADMIN);

        when(userService.updateUser(anyString(), any(UpdateUserRequest.class))).thenReturn(Optional.of(user));

        performPutSuccess("/api/v1/users/testuser", updateUserRequest)
                .andExpect(jsonPath("$.data", equalTo("User updated successfully")))
                .andExpect(jsonPath("$.message", equalTo("Request was successful")));

        verify(userService, times(1)).updateUser(anyString(), any(UpdateUserRequest.class));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    public void testUpdateUser_MissingFields() throws Exception {
        UpdateUserRequest updateUserRequest = new UpdateUserRequest();

        performPutBadRequest("/api/v1/users/testuser", updateUserRequest);
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    public void testDisableUser_Success() throws Exception {
        User user = createUser("testuser", Role.ROLE_USER);

        when(userService.getUserByUsername(anyString())).thenReturn(Optional.of(user));
        doNothing().when(userService).updateUserEnabledStatus(anyString(), eq(false));

        performPutSuccess("/api/v1/users/testuser/disable", null)
                .andExpect(jsonPath("$.message", equalTo("Request was successful")))
                .andExpect(jsonPath("$.data", equalTo("User disabled successfully")));

        verify(userService, times(1)).getUserByUsername(anyString());
        verify(userService, times(1)).updateUserEnabledStatus(anyString(), eq(false));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    public void testDisableUser_NonExistentUser() throws Exception {
        when(userService.getUserByUsername(anyString())).thenReturn(Optional.empty());

        performPutNotFound("/api/v1/users/testuser/disable");

        verify(userService, times(1)).getUserByUsername(anyString());
        verify(userService, never()).updateUserEnabledStatus(anyString(), eq(false));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    public void testEnableUser_Success() throws Exception {
        User user = createUser("testuser", Role.ROLE_USER);

        when(userService.getUserByUsername(anyString())).thenReturn(Optional.of(user));
        doNothing().when(userService).updateUserEnabledStatus(anyString(), eq(true));

        performPutSuccess("/api/v1/users/testuser/enable", null)
                .andExpect(jsonPath("$.message", equalTo("Request was successful")))
                .andExpect(jsonPath("$.data", equalTo("User enabled successfully")));

        verify(userService, times(1)).getUserByUsername(anyString());
        verify(userService, times(1)).updateUserEnabledStatus(anyString(), eq(true));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    public void testEnableUser_NonExistentUser() throws Exception {
        when(userService.getUserByUsername(anyString())).thenReturn(Optional.empty());

        performPutNotFound("/api/v1/users/testuser/enable");

        verify(userService, times(1)).getUserByUsername(anyString());
        verify(userService, never()).updateUserEnabledStatus(anyString(), eq(true));
    }

    private RegisterRequest createValidRegisterRequest() {
        return createRegisterRequest("newuser", "password123");
    }

    private RegisterRequest createRegisterRequest(String username, String password) {
        RegisterRequest request = new RegisterRequest();
        request.setUsername(username);
        request.setPassword(password);
        request.setRole(Role.ROLE_USER);
        request.setFirstName("testfirstname");
        return request;
    }

    private User createUser(String username, Role role) {
        return User.builder()
                .username(username)
                .password("password")
                .firstName("First")
                .lastName("Last")
                .role(role)
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .build();
    }

    private ResultActions performPostSuccess(Object request) throws Exception {
        return mockMvc.perform(post("/api/v1/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated());
    }

    private void performPostBadRequest(Object request) throws Exception {
        mockMvc.perform(post("/api/v1/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    private void performPutConflictRequest(Object request) throws Exception {
        mockMvc.perform(post("/api/v1/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isConflict());
    }

    private ResultActions performPutSuccess(String url, Object request) throws Exception {
        return mockMvc.perform(put(url)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
    }

    private void performPutBadRequest(String url, Object request) throws Exception {
        mockMvc.perform(put(url)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    private void performPutNotFound(String url) throws Exception {
        mockMvc.perform(put(url)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(null)))
                .andExpect(status().isNotFound());
    }

    @Override
    public void close() throws Exception {
        mocks.close();
    }
}
