package com.demo.userlogin.springsecuritylogin.integration_tests;

import jakarta.transaction.Transactional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.reactive.server.WebTestClient;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
public class AdminFunctionTest {

    @Autowired
    private WebTestClient webTestClient;

    private String adminToken;
    private String userToken;

    private final String api = "/api/v1/admin/hello";

    @BeforeEach
    void setUp() {
        adminToken = TestUtils.login(webTestClient, "admin1", "admin123").getToken();
        userToken = TestUtils.login(webTestClient, "user1", "user123").getToken();
    }

    @Test
    void whenAdminAccessAdminEndpoint_thenStatus200() {
        webTestClient.get().uri(api)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo("Heyyyyyyy, You are an Admin admin1!");
    }

    @Test
    void whenUserAccessAdminEndpoint_thenStatusForbidden() {
        webTestClient.get().uri(api)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + userToken)
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void whenAdminEndpointAccessedWithoutLogin_thenStatusUnAuthorized() {
        webTestClient.get().uri(api)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + "invalid_token")
                .exchange()
                .expectStatus().isUnauthorized();
    }
}
