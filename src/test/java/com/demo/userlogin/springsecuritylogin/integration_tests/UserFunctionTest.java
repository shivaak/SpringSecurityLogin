package com.demo.userlogin.springsecuritylogin.integration_tests;

import com.demo.userlogin.springsecuritylogin.dto.RegisterRequest;
import com.demo.userlogin.springsecuritylogin.dto.UpdateProfileRequest;
import com.demo.userlogin.springsecuritylogin.dto.UpdateUserRequest;
import com.demo.userlogin.springsecuritylogin.model.Role;
import jakarta.transaction.Transactional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
public class UserFunctionTest {

    @Autowired
    private WebTestClient webTestClient;

    private String adminToken;
    private String userToken;

    @BeforeEach
    void setUp() {
        adminToken = TestUtils.login(webTestClient, "admin1", "admin123").getToken();
        userToken = TestUtils.login(webTestClient, "user1", "user123").getToken();
    }

    @Test
    void whenRegisterUserWithAdminRole_thenStatus201() {
        RegisterRequest registerRequest = RegisterRequest.builder()
                .username("newuser")
                .password("newuser123")
                .firstName("New")
                .lastName("User")
                .role(Role.ROLE_USER)
                .build();

        webTestClient.post().uri("/api/v1/users/register")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(registerRequest)
                .exchange()
                .expectStatus().isCreated();
    }

    @Test
    void whenRegisterUserWithExistingUsername_thenStatus400() {
        RegisterRequest registerRequest = RegisterRequest.builder()
                .username("user1")  // existing username
                .password("password123")
                .firstName("User")
                .lastName("One")
                .role(Role.ROLE_USER)
                .build();

        webTestClient.post().uri("/api/v1/users/register")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(registerRequest)
                .exchange()
                .expectStatus().isEqualTo(409); // Conflict
    }

    @Test
    void whenRegisterUserWithInvalidData_thenStatus400() {
        RegisterRequest registerRequest = RegisterRequest.builder()
                .username("")  // Invalid username
                .password("short")
                .firstName("")
                .lastName("")
                .role(Role.ROLE_USER)
                .build();

        webTestClient.post().uri("/api/v1/users/register")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(registerRequest)
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void whenUpdateProfileWithUserRole_thenStatus200() {
        UpdateProfileRequest updateProfileRequest = UpdateProfileRequest.builder()
                .firstName("Updated")
                .lastName("User")
                .build();

        webTestClient.put().uri("/api/v1/users/profile")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + userToken)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(updateProfileRequest)
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void whenUpdateProfileWithInvalidData_thenStatus400() {
        UpdateProfileRequest updateProfileRequest = UpdateProfileRequest.builder()
                .firstName("")  // Invalid data
                .lastName("")
                .build();

        webTestClient.put().uri("/api/v1/users/profile")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + userToken)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(updateProfileRequest)
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void whenUpdateProfileWithoutAuthentication_thenStatus401() {
        UpdateProfileRequest updateProfileRequest = UpdateProfileRequest.builder()
                .firstName("Updated")
                .lastName("User")
                .build();

        webTestClient.put().uri("/api/v1/users/profile")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(updateProfileRequest)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void whenAdminUpdatesNonExistentUser_thenStatus404() {
        UpdateUserRequest updateUserRequest = UpdateUserRequest.builder()
                .role(Role.ROLE_USER)
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .build();

        webTestClient.put().uri("/api/v1/users/nonexistent")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(updateUserRequest)
                .exchange()
                .expectStatus().isNotFound();
    }

    @Test
    void whenUpdateUserWithoutAuthentication_thenStatus401() {
        UpdateUserRequest updateUserRequest = UpdateUserRequest.builder()
                .role(Role.ROLE_USER)
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .build();

        webTestClient.put().uri("/api/v1/users/user1")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(updateUserRequest)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void whenUpdateUserWithoutAdminPrivileges_thenStatus403() {
        UpdateUserRequest updateUserRequest = UpdateUserRequest.builder()
                .role(Role.ROLE_USER)
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .build();

        webTestClient.put().uri("/api/v1/users/user1")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + userToken) // Regular user token
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(updateUserRequest)
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void whenAdminDisablesUser_thenStatus200() {
        webTestClient.put().uri("/api/v1/users/user1/disable")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void whenAdminDisablesNonExistentUser_thenStatus404() {
        webTestClient.put().uri("/api/v1/users/nonexistent/disable")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                .exchange()
                .expectStatus().isNotFound();
    }

    @Test
    void whenDisableUserWithoutAdminPrivileges_thenStatus403() {
        webTestClient.put().uri("/api/v1/users/user1/disable")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + userToken) // Regular user token
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void whenAdminEnablesUser_thenStatus200() {
        webTestClient.put().uri("/api/v1/users/user1/enable")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void whenAdminEnablesNonExistentUser_thenStatus404() {
        webTestClient.put().uri("/api/v1/users/nonexistent/enable")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                .exchange()
                .expectStatus().isNotFound();
    }

    @Test
    void whenEnableUserWithoutAdminPrivileges_thenStatus403() {
        webTestClient.put().uri("/api/v1/users/user1/enable")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + userToken) // Regular user token
                .exchange()
                .expectStatus().isForbidden();
    }
}
