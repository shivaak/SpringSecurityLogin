package com.demo.userlogin.springsecuritylogin.integration_tests;

import com.demo.userlogin.springsecuritylogin.dto.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import jakarta.transaction.Transactional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mockStatic;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
public class AuthFunctionTest {

    @Autowired
    private WebTestClient webTestClient;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private Cache<String, Boolean> accessTokenBlacklistCache; // Inject the cache

    @BeforeEach
    void setUp() {
        accessTokenBlacklistCache.invalidateAll(); // Clear the cache before each test
    }


    @Test
    void whenLoginWithValidCredentials_thenStatus200() {
        LoginRequest loginRequest = LoginRequest.builder()
                .username("admin1")
                .password("admin123")
                .build();

        webTestClient.post().uri("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(loginRequest)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.data.token").isNotEmpty()
                .jsonPath("$.data.refreshToken").isNotEmpty()
                .jsonPath("$.message").isEqualTo("Request was successful")
                .jsonPath("$.success").isEqualTo(true);
    }

    @Test
    void whenLoginWithInvalidCredentials_thenStatus401() {
        LoginRequest loginRequest = LoginRequest.builder()
                .username("admin1")
                .password("wrongpassword")
                .build();

        webTestClient.post().uri("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(loginRequest)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void whenLoginWithMissingCredentials_thenStatus400() {
        LoginRequest loginRequest = LoginRequest.builder().build();

        webTestClient.post().uri("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(loginRequest)
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void whenGetAccessTokenWithRefreshToken_thenStatus200() throws JsonProcessingException, InterruptedException {
        // First login to get refresh token
        LoginRequest loginRequest = LoginRequest.builder()
                .username("user1")
                .password("user123")
                .build();

        String response = webTestClient.post().uri("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(loginRequest)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .returnResult()
                .getResponseBody();

        // Parse the response
        JsonNode jsonResponse = objectMapper.readTree(response);
        String accessToken = jsonResponse.path("data").path("token").asText();
        String refreshToken = jsonResponse.path("data").path("refreshToken").asText();

        // Add a delay to ensure new token generation
        Thread.sleep(1000);

        assertThat(accessToken).isNotEmpty();
        assertThat(refreshToken).isNotEmpty();

        RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest(refreshToken);

        response = webTestClient.post().uri("/api/v1/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(refreshTokenRequest)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .returnResult()
                .getResponseBody();

        // Parse the response
        StandardResponse<RefreshTokenResponse> refreshResponse = objectMapper.readValue(response,
                objectMapper.getTypeFactory().constructParametricType(StandardResponse.class,
                        RefreshTokenResponse.class));

        // Extract tokens
        String newAccessToken = refreshResponse.getData().getToken();
        String newRefreshToken = refreshResponse.getData().getRefreshToken();
        assertThat(newAccessToken).isNotEmpty();
        assertThat(newAccessToken).isNotEqualTo(accessToken);
        assertThat(newRefreshToken).isNull();
    }

    @Test
    void whenRefreshWithInvalidToken_thenStatus401() {
        RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest("invalidRefreshToken");

        webTestClient.post().uri("/api/v1/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(refreshTokenRequest)
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void whenRefreshWithExpiredRefreshToken_thenStatusBadRequest() throws JsonProcessingException {
        try (MockedStatic<Instant> mockedInstant = mockStatic(Instant.class, CALLS_REAL_METHODS)) {
            Instant now = Instant.now();
            mockedInstant.when(Instant::now).thenReturn(now);

            // First login to get refresh token
            LoginRequest loginRequest = LoginRequest.builder()
                    .username("user1")
                    .password("user123")
                    .build();

            String response = webTestClient.post().uri("/api/v1/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(loginRequest)
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .returnResult()
                    .getResponseBody();

            // Parse the response
            JsonNode jsonResponse = objectMapper.readTree(response);
            String refreshToken = jsonResponse.path("data").path("refreshToken").asText();
            String accessToken = jsonResponse.path("data").path("token").asText();

            assertThat(accessToken).isNotEmpty();
            assertThat(refreshToken).isNotEmpty();

            // Simulate token expiration by advancing time - expire time for refresh token in integration test is 5 minutes(application.yaml)
            Instant future = now.plus(Duration.ofMinutes(10));
            mockedInstant.when(Instant::now).thenReturn(future);

            RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest(refreshToken);

            //Passing expired token
            webTestClient.post().uri("/api/v1/auth/refresh")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(refreshTokenRequest)
                    .exchange()
                    .expectStatus().isBadRequest()
                    .expectBody()
                    .jsonPath("$.errorMessage").isEqualTo("Token is expired");
        }
    }

    @Test
    void whenRefreshWithAccessToken_thenStatus401() throws JsonProcessingException {
        // First login to get access token
        LoginRequest loginRequest = LoginRequest.builder()
                .username("user1")
                .password("user123")
                .build();

        String response = webTestClient.post().uri("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(loginRequest)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .returnResult()
                .getResponseBody();

        // Parse the response
        JsonNode jsonResponse = objectMapper.readTree(response);
        String accessToken = jsonResponse.path("data").path("token").asText();

        assertThat(accessToken).isNotEmpty();

        // Attempt to use access token as refresh token
        RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest(accessToken);

        webTestClient.post().uri("/api/v1/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(refreshTokenRequest)
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.errorMessage").isEqualTo("Invalid token for refresh");
    }

    @Test
    void whenAccessSecuredAPiWithRefreshToken_thenStatus401() throws JsonProcessingException {
        // First login to get refresh token
        LoginRequest loginRequest = LoginRequest.builder()
                .username("user1")
                .password("user123")
                .build();

        String response = webTestClient.post().uri("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(loginRequest)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .returnResult()
                .getResponseBody();

        // Parse the response
        JsonNode jsonResponse = objectMapper.readTree(response);
        String refreshToken = jsonResponse.path("data").path("refreshToken").asText();

        assertThat(refreshToken).isNotEmpty();

        webTestClient.get().uri("/api/v1/admin/hello")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + refreshToken)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void whenLogoutWithValidTokens_thenStatus200() throws JsonProcessingException {
        // First login to get tokens
        LoginRequest loginRequest = LoginRequest.builder()
                .username("user1")
                .password("user123")
                .build();

        String response = webTestClient.post().uri("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(loginRequest)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .returnResult()
                .getResponseBody();

        // Parse the response
        JsonNode jsonResponse = objectMapper.readTree(response);
        String accessToken = jsonResponse.path("data").path("token").asText();
        String refreshToken = jsonResponse.path("data").path("refreshToken").asText();

        assertThat(accessToken).isNotEmpty();
        assertThat(refreshToken).isNotEmpty();

        // Perform logout
        LogoutRequest logoutRequest = new LogoutRequest(refreshToken);

        webTestClient.post().uri("/api/v1/auth/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .bodyValue(logoutRequest)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.message").isEqualTo("Logout successful")
                .jsonPath("$.success").isEqualTo(true);
    }

    @Test
    void whenLogoutWithInvalidTokens_thenStatus401() {
        LogoutRequest logoutRequest = new LogoutRequest("invalidRefreshToken");

        webTestClient.post().uri("/api/v1/auth/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, "Bearer invalidAccessToken")
                .bodyValue(logoutRequest)
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody()
                .jsonPath("$.errorMessage").isEqualTo("Invalid or expired token");
    }

    @Test
    void whenAccessAdminEndpointWithoutToken_thenStatus401() {
        webTestClient.get().uri("/api/v1/admin/hello")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody()
                .jsonPath("$.errorMessage").isEqualTo("Authentication failed. Full authentication is required to access this resource");
    }

    @Test
    void whenAccessAdminEndpointWithUserToken_thenStatus403() throws JsonProcessingException {
        // First login as user to get token
        LoginRequest loginRequest = LoginRequest.builder()
                .username("user1")
                .password("user123")
                .build();

        String response = webTestClient.post().uri("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(loginRequest)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .returnResult()
                .getResponseBody();

        // Parse the response
        JsonNode jsonResponse = objectMapper.readTree(response);
        String userToken = jsonResponse.path("data").path("token").asText();

        assertThat(userToken).isNotEmpty();

        // Attempt to access admin endpoint with user token
        webTestClient.get().uri("/api/v1/admin/hello")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + userToken)
                .exchange()
                .expectStatus().isForbidden()
                .expectBody()
                .jsonPath("$.errorMessage").isEqualTo("Access Denied");
    }

    @Test
    void whenAccessAdminEndpointWithAdminToken_thenStatus200() throws JsonProcessingException {
        // First login as admin to get token
        LoginRequest loginRequest = LoginRequest.builder()
                .username("admin1")
                .password("admin123")
                .build();

        String response = webTestClient.post().uri("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(loginRequest)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .returnResult()
                .getResponseBody();

        // Parse the response
        JsonNode jsonResponse = objectMapper.readTree(response);
        String adminToken = jsonResponse.path("data").path("token").asText();

        assertThat(adminToken).isNotEmpty();

        // Access admin endpoint with admin token
        webTestClient.get().uri("/api/v1/admin/hello")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo("Heyyyyyyy, You are an Admin admin1!");
    }

    @Test
    void whenAttemptSQLInjection_thenStatus400() {
        LoginRequest loginRequest = LoginRequest.builder()
                .username("admin1' OR '1'='1")
                .password("admin123")
                .build();

        webTestClient.post().uri("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(loginRequest)
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.errorMessage").isEqualTo("Validation failed");

    }

    @Test
    void whenAttemptXSSAttack_thenStatus400() {
        LoginRequest loginRequest = LoginRequest.builder()
                .username("<script>alert('XSS')</script>")
                .password("admin123")
                .build();

        webTestClient.post().uri("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(loginRequest)
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.errorMessage").isEqualTo("Validation failed");
    }

    @Test
    void whenUsingExpiredAccessToken_thenStatus401_ThenGetNewTokenUsingRefresh() throws JsonProcessingException {
        try (MockedStatic<Instant> mockedInstant = mockStatic(Instant.class, CALLS_REAL_METHODS)) {
            Instant now = Instant.now();
            mockedInstant.when(Instant::now).thenReturn(now);

            // First login to get tokens
            LoginRequest loginRequest = LoginRequest.builder()
                    .username("admin1")
                    .password("admin123")
                    .build();

            String response = webTestClient.post().uri("/api/v1/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(loginRequest)
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .returnResult()
                    .getResponseBody();

            // Add a delay to ensure new token generation
            Thread.sleep(500);

            // Parse the response
            JsonNode jsonResponse = objectMapper.readTree(response);
            String accessToken = jsonResponse.path("data").path("token").asText();
            String refreshToken = jsonResponse.path("data").path("refreshToken").asText();

            assertThat(accessToken).isNotEmpty();
            assertThat(refreshToken).isNotEmpty();

            //Access Admin URL before expiry
            webTestClient.get().uri("/api/v1/admin/hello")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody(String.class).isEqualTo("Heyyyyyyy, You are an Admin admin1!");

            // Simulate token expiration by advancing time - expire time for access token in integration test is 5 minutes (application.yaml)
            Instant future = now.plus(Duration.ofMinutes(6));
            mockedInstant.when(Instant::now).thenReturn(future);

            // Attempt to access an endpoint with expired token
            webTestClient.get().uri("/api/v1/admin/hello")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                    .exchange()
                    .expectStatus().isUnauthorized()
                    .expectBody()
                    .jsonPath("$.errorMessage").isEqualTo("Invalid or expired token");

            // Get new token using refresh token
            RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest(refreshToken);

            response = webTestClient.post().uri("/api/v1/auth/refresh")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(refreshTokenRequest)
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .returnResult()
                    .getResponseBody();
            Thread.sleep(500);

            // Parse the response
            StandardResponse<RefreshTokenResponse> refreshResponse = objectMapper.readValue(response,
                    objectMapper.getTypeFactory().constructParametricType(StandardResponse.class,
                            RefreshTokenResponse.class));

            // Extract tokens
            String newAccessToken = refreshResponse.getData().getToken();
            String newRefreshToken = refreshResponse.getData().getRefreshToken();
            // Refresh token should not be changed
            assertThat(newRefreshToken).isNull();
            assertThat(newAccessToken).isNotEmpty();
            assertThat(newAccessToken).isNotEqualTo(accessToken);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void whenUsingBlacklistedAccessToken_thenStatus401() throws JsonProcessingException {
        // First login to get tokens
        LoginRequest loginRequest = LoginRequest.builder()
                .username("user1")
                .password("user123")
                .build();

        String response = webTestClient.post().uri("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(loginRequest)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .returnResult()
                .getResponseBody();

        // Parse the response
        JsonNode jsonResponse = objectMapper.readTree(response);
        String accessToken = jsonResponse.path("data").path("token").asText();
        String refreshToken = jsonResponse.path("data").path("refreshToken").asText();

        assertThat(accessToken).isNotEmpty();
        assertThat(refreshToken).isNotEmpty();

        // Blacklist the token
        // Perform logout
        LogoutRequest logoutRequest = new LogoutRequest(refreshToken);

        webTestClient.post().uri("/api/v1/auth/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .bodyValue(logoutRequest)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.message").isEqualTo("Logout successful")
                .jsonPath("$.success").isEqualTo(true);

        // Attempt to access an endpoint with blacklisted token
        webTestClient.get().uri("/api/v1/admin/hello")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void whenLogoutLoggedInUser_thenStatus200() throws JsonProcessingException,
                                                       InterruptedException {
        // First login to get tokens
        LoginRequest loginRequest = LoginRequest.builder()
                .username("user1")
                .password("user123")
                .build();

        String response = webTestClient.post().uri("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(loginRequest)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .returnResult()
                .getResponseBody();

        Thread.sleep(500);

        // Parse the response
        JsonNode jsonResponse = objectMapper.readTree(response);
        String accessToken = jsonResponse.path("data").path("token").asText();
        String refreshToken = jsonResponse.path("data").path("refreshToken").asText();

        assertThat(accessToken).isNotEmpty();
        assertThat(refreshToken).isNotEmpty();


        // Perform logout
        LogoutRequest logoutRequest = new LogoutRequest(refreshToken);

        webTestClient.post().uri("/api/v1/auth/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .bodyValue(logoutRequest)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.message").isEqualTo("Logout successful")
                .jsonPath("$.success").isEqualTo(true);
    }

    @Test
    void whenLoggedOutUserUsesAccessToken_thenStatus401() throws JsonProcessingException {
        // First login to get tokens
        LoginRequest loginRequest = LoginRequest.builder()
                .username("user1")
                .password("user123")
                .build();

        String response = webTestClient.post().uri("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(loginRequest)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .returnResult()
                .getResponseBody();

        // Parse the response
        JsonNode jsonResponse = objectMapper.readTree(response);
        String accessToken = jsonResponse.path("data").path("token").asText();
        String refreshToken = jsonResponse.path("data").path("refreshToken").asText();

        assertThat(accessToken).isNotEmpty();
        assertThat(refreshToken).isNotEmpty();

        // Perform logout
        LogoutRequest logoutRequest = new LogoutRequest(refreshToken);

        webTestClient.post().uri("/api/v1/auth/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .bodyValue(logoutRequest)
                .exchange()
                .expectStatus().isOk();

        // Attempt to access secured resource with logged-out access token
        webTestClient.get().uri("/api/v1/admin/hello")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void whenLoggedOutUserUsesRefreshToken_thenStatus401() throws JsonProcessingException {
        // First login to get tokens
        LoginRequest loginRequest = LoginRequest.builder()
                .username("user1")
                .password("user123")
                .build();

        String response = webTestClient.post().uri("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(loginRequest)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .returnResult()
                .getResponseBody();

        // Parse the response
        JsonNode jsonResponse = objectMapper.readTree(response);
        String accessToken = jsonResponse.path("data").path("token").asText();
        String refreshToken = jsonResponse.path("data").path("refreshToken").asText();

        assertThat(accessToken).isNotEmpty();
        assertThat(refreshToken).isNotEmpty();

        // Perform logout
        LogoutRequest logoutRequest = new LogoutRequest(refreshToken);

        webTestClient.post().uri("/api/v1/auth/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .bodyValue(logoutRequest)
                .exchange()
                .expectStatus().isOk();

        // Attempt to use logged-out refresh token
        RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest(refreshToken);

        webTestClient.post().uri("/api/v1/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(refreshTokenRequest)
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void whenLogoutWithOnlyAccessToken_thenStatus400() throws JsonProcessingException {
        // First login to get tokens
        LoginRequest loginRequest = LoginRequest.builder()
                .username("user1")
                .password("user123")
                .build();

        String response = webTestClient.post().uri("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(loginRequest)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .returnResult()
                .getResponseBody();

        // Parse the response
        JsonNode jsonResponse = objectMapper.readTree(response);
        String accessToken = jsonResponse.path("data").path("token").asText();
        String refreshToken = jsonResponse.path("data").path("refreshToken").asText();

        assertThat(accessToken).isNotEmpty();
        assertThat(refreshToken).isNotEmpty();

        LogoutRequest logoutRequest = new LogoutRequest(null); // No refresh token

        webTestClient.post().uri("/api/v1/auth/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .bodyValue(logoutRequest)
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void whenLogoutWithOnlyRefreshToken_thenStatusUnAuthorized() throws JsonProcessingException {
        // First login to get tokens
        LoginRequest loginRequest = LoginRequest.builder()
                .username("user1")
                .password("user123")
                .build();

        String response = webTestClient.post().uri("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(loginRequest)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .returnResult()
                .getResponseBody();

        // Parse the response
        JsonNode jsonResponse = objectMapper.readTree(response);
        String accessToken = jsonResponse.path("data").path("token").asText();
        String refreshToken = jsonResponse.path("data").path("refreshToken").asText();

        assertThat(accessToken).isNotEmpty();
        assertThat(refreshToken).isNotEmpty();

        LogoutRequest logoutRequest = new LogoutRequest(refreshToken); // No access token

        webTestClient.post().uri("/api/v1/auth/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(logoutRequest)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void whenLogoutWithAccessTokenAndOtherUsersRefreshToken_thenStatus401() throws JsonProcessingException {
        // First login to get tokens for user1
        LoginRequest loginRequest1 = LoginRequest.builder()
                .username("user1")
                .password("user123")
                .build();

        String response1 = webTestClient.post().uri("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(loginRequest1)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .returnResult()
                .getResponseBody();

        JsonNode jsonResponse1 = objectMapper.readTree(response1);
        String accessToken1 = jsonResponse1.path("data").path("token").asText();
        String refreshToken1 = jsonResponse1.path("data").path("refreshToken").asText();

        assertThat(accessToken1).isNotEmpty();
        assertThat(refreshToken1).isNotEmpty();

        // First login to get tokens for user2
        LoginRequest loginRequest2 = LoginRequest.builder()
                .username("user2")
                .password("user123")
                .build();

        String response2 = webTestClient.post().uri("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(loginRequest2)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .returnResult()
                .getResponseBody();

        JsonNode jsonResponse2 = objectMapper.readTree(response2);
        String refreshToken2 = jsonResponse2.path("data").path("refreshToken").asText();

        assertThat(refreshToken2).isNotEmpty();

        // Attempt to logout with user1's access token and user2's refresh token
        LogoutRequest logoutRequest = new LogoutRequest(refreshToken2);

        webTestClient.post().uri("/api/v1/auth/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken1)
                .bodyValue(logoutRequest)
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void whenLogoutWithRefreshTokenAndOtherUsersAccessToken_thenStatus401() throws JsonProcessingException {
        // First login to get tokens for user1
        LoginRequest loginRequest1 = LoginRequest.builder()
                .username("user1")
                .password("user123")
                .build();

        String response1 = webTestClient.post().uri("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(loginRequest1)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .returnResult()
                .getResponseBody();

        JsonNode jsonResponse1 = objectMapper.readTree(response1);
        String accessToken1 = jsonResponse1.path("data").path("token").asText();
        String refreshToken1 = jsonResponse1.path("data").path("refreshToken").asText();

        assertThat(accessToken1).isNotEmpty();
        assertThat(refreshToken1).isNotEmpty();

        // First login to get tokens for user2
        LoginRequest loginRequest2 = LoginRequest.builder()
                .username("user2")
                .password("user123")
                .build();

        String response2 = webTestClient.post().uri("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(loginRequest2)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .returnResult()
                .getResponseBody();

        JsonNode jsonResponse2 = objectMapper.readTree(response2);
        String refreshToken2 = jsonResponse2.path("data").path("refreshToken").asText();
        String accessToken2 = jsonResponse2.path("data").path("token").asText();

        assertThat(refreshToken2).isNotEmpty();

        // Attempt to log out with user1's access token and user2's refresh token
        LogoutRequest logoutRequest = new LogoutRequest(refreshToken1);

        webTestClient.post().uri("/api/v1/auth/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken2)
                .bodyValue(logoutRequest)
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void whenLogoutWithSwappedTokens_thenStatus401() throws JsonProcessingException {
        // First login to get tokens
        LoginRequest loginRequest = LoginRequest.builder()
                .username("user1")
                .password("user123")
                .build();

        String response = webTestClient.post().uri("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(loginRequest)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .returnResult()
                .getResponseBody();

        // Parse the response
        JsonNode jsonResponse = objectMapper.readTree(response);
        String accessToken = jsonResponse.path("data").path("token").asText();
        String refreshToken = jsonResponse.path("data").path("refreshToken").asText();

        assertThat(accessToken).isNotEmpty();
        assertThat(refreshToken).isNotEmpty();

        // Attempt to logout with swapped tokens
        LogoutRequest logoutRequest = new LogoutRequest(accessToken); // Using access token as refresh token

        webTestClient.post().uri("/api/v1/auth/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + refreshToken) // Using refresh token as access token
                .bodyValue(logoutRequest)
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody()
                .jsonPath("$.errorMessage").isEqualTo("Invalid token type for accessing secured API");
    }

    @Test
    void whenLogoutWithoutProvidingTokens_thenStatusUnAuthorized() {
        LogoutRequest logoutRequest = new LogoutRequest(null);

        webTestClient.post().uri("/api/v1/auth/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(logoutRequest)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void whenLogoutWithMalformedTokens_thenStatus401() {
        LogoutRequest logoutRequest = new LogoutRequest("malformedRefreshToken");

        webTestClient.post().uri("/api/v1/auth/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, "Bearer malformedAccessToken")
                .bodyValue(logoutRequest)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void whenLogoutWithExpiredAccessToken_thenStatus401() throws JsonProcessingException, InterruptedException {
        try (MockedStatic<Instant> mockedInstant = mockStatic(Instant.class, CALLS_REAL_METHODS)) {
            Instant now = Instant.now();
            mockedInstant.when(Instant::now).thenReturn(now);
            // First login to get tokens
            LoginRequest loginRequest = LoginRequest.builder()
                    .username("user1")
                    .password("user123")
                    .build();

            String response = webTestClient.post().uri("/api/v1/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(loginRequest)
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .returnResult()
                    .getResponseBody();

            // Parse the response
            JsonNode jsonResponse = objectMapper.readTree(response);
            String accessToken = jsonResponse.path("data").path("token").asText();
            String refreshToken = jsonResponse.path("data").path("refreshToken").asText();

            assertThat(accessToken).isNotEmpty();
            assertThat(refreshToken).isNotEmpty();

            // Simulate token expiration by advancing time - expire time for refresh token in integration test is 5 minutes(application.yaml)
            Instant future = now.plus(Duration.ofMinutes(6));
            mockedInstant.when(Instant::now).thenReturn(future);

            // Perform logout with expired tokens
            LogoutRequest logoutRequest = new LogoutRequest(refreshToken);

            webTestClient.post().uri("/api/v1/auth/logout")
                    .contentType(MediaType.APPLICATION_JSON)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                    .bodyValue(logoutRequest)
                    .exchange()
                    .expectStatus().isUnauthorized()
                    .expectBody()
                    .jsonPath("$.errorMessage").isEqualTo("Invalid or expired token");
        }
    }


    @Test
    void whenRepeatedLogoutAttempts_thenStatus401OnSubsequentAttempts() throws JsonProcessingException {
        // First login to get tokens
        LoginRequest loginRequest = LoginRequest.builder()
                .username("user1")
                .password("user123")
                .build();

        String response = webTestClient.post().uri("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(loginRequest)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .returnResult()
                .getResponseBody();

        // Parse the response
        JsonNode jsonResponse = objectMapper.readTree(response);
        String accessToken = jsonResponse.path("data").path("token").asText();
        String refreshToken = jsonResponse.path("data").path("refreshToken").asText();

        assertThat(accessToken).isNotEmpty();
        assertThat(refreshToken).isNotEmpty();

        // Perform first logout
        LogoutRequest logoutRequest = new LogoutRequest(refreshToken);

        webTestClient.post().uri("/api/v1/auth/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .bodyValue(logoutRequest)
                .exchange()
                .expectStatus().isOk();

        // Perform second logout attempt with the same tokens
        webTestClient.post().uri("/api/v1/auth/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .bodyValue(logoutRequest)
                .exchange()
                .expectStatus().isUnauthorized();
    }




}
