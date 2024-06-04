package com.demo.userlogin.springsecuritylogin.controller;

import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.demo.userlogin.springsecuritylogin.config.TestSecurityConfig;
import com.demo.userlogin.springsecuritylogin.dto.LoginRequest;
import com.demo.userlogin.springsecuritylogin.dto.LoginResponse;
import com.demo.userlogin.springsecuritylogin.dto.LogoutRequest;
import com.demo.userlogin.springsecuritylogin.dto.RefreshTokenRequest;
import com.demo.userlogin.springsecuritylogin.security.JwtDecoder;
import com.demo.userlogin.springsecuritylogin.security.JwtToUserPrincipalConverter;
import com.demo.userlogin.springsecuritylogin.security.UserPrincipal;
import com.demo.userlogin.springsecuritylogin.service.AuthService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collections;

import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
@Import(TestSecurityConfig.class)
public class AuthControllerTest implements AutoCloseable {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuthService authService;

    @MockBean
    private JwtDecoder jwtDecoder;

    @MockBean
    private JwtToUserPrincipalConverter jwtToUserPrincipalConverter;

    @MockBean(name = "accessTokenBlacklistCache")
    private Cache<String, Boolean> accessTokenBlacklistCache;

    @MockBean(name = "refreshTokenBlacklistCache")
    private Cache<String, Boolean> refreshTokenBlacklistCache;

    @Autowired
    private ObjectMapper objectMapper;

    @Mock
    private DecodedJWT decodedJWT;

    @Mock
    private Claim usernameClaim;

    @Mock
    private Claim typeClaim;

    private AutoCloseable mocks;

    @BeforeEach
    public void setUp() {
        mocks = MockitoAnnotations.openMocks(this);

        // Mock the decodedJWT to return non-null claims
        when(jwtDecoder.decode(anyString())).thenReturn(decodedJWT);
        when(decodedJWT.getClaim("username")).thenReturn(usernameClaim);
        when(usernameClaim.asString()).thenReturn("testuser");
        when(decodedJWT.getClaim("type")).thenReturn(typeClaim);
        when(typeClaim.asString()).thenReturn("access");

        // Mock the JwtToUserPrincipalConverter to return a valid UserPrincipal
        UserPrincipal userPrincipal = UserPrincipal.builder().username("testuser")
                .authorities(Collections.emptyList())
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .enabled(true)
                .build();
        when(jwtToUserPrincipalConverter.convert(any(DecodedJWT.class))).thenReturn(userPrincipal);
    }

    @Test
    public void testLogin_Success() throws Exception {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername("testuser");
        loginRequest.setPassword("password");

        LoginResponse loginResponse = new LoginResponse("access-token", "refresh-token");

        when(authService.login(any(LoginRequest.class))).thenReturn(loginResponse);

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.token", equalTo("access-token")))
                .andExpect(jsonPath("$.data.refreshToken", equalTo("refresh-token")));

        verify(authService, times(1)).login(any(LoginRequest.class));
    }

    @Test
    public void testRefresh_Success() throws Exception {
        RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest();
        refreshTokenRequest.setRefreshToken("refresh-token");

        LoginResponse loginResponse = new LoginResponse("new-access-token", "new-refresh-token");

        when(authService.refresh(anyString())).thenReturn(loginResponse);

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshTokenRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.token", equalTo("new-access-token")))
                .andExpect(jsonPath("$.data.refreshToken", equalTo("new-refresh-token")));

        verify(authService, times(1)).refresh(anyString());
    }

    @Test
    public void testLogout_Success() throws Exception {
        LogoutRequest logoutRequest = new LogoutRequest();
        logoutRequest.setRefreshToken("refresh-token");

        mockMvc.perform(post("/api/v1/auth/logout")
                        .header("Authorization", "Bearer access-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(logoutRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data", equalTo("Logout successful")));

        verify(authService, times(1)).logout(anyString(), anyString());
    }

    @Test
    public void testLogout_MissingAuthorizationHeader() throws Exception {
        LogoutRequest logoutRequest = new LogoutRequest();
        logoutRequest.setRefreshToken("refresh-token");

        mockMvc.perform(post("/api/v1/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(logoutRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.data", equalTo("Token not found")));

        verify(authService, never()).logout(anyString(), anyString());
    }

    @Override
    public void close() throws Exception {
        mocks.close();
    }
}
