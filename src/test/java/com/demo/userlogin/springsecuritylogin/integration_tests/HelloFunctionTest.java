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
public class HelloFunctionTest {

    @Autowired
    private WebTestClient webTestClient;

    private String adminToken;
    private String userToken;

    private final String api = "/api/v1/hello";

    @BeforeEach
    void setUp() {
        adminToken = TestUtils.login(webTestClient, "admin1", "admin123").getToken();
        userToken = TestUtils.login(webTestClient, "user1", "user123").getToken();
    }

    @Test
    void whenAdminAccessHelloEndpoint_thenStatus200() {
        webTestClient.get().uri(api)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo("Hello, admin1!");
    }

    @Test
    void whenUserAccessHelloEndpoint_thenStatus200() {
        webTestClient.get().uri(api)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + userToken)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo("Hello, user1!");
    }

    @Test
    void whenAdminEndpointAccessedWithoutLogin_thenStatusUnAuthorized() {
        webTestClient.get().uri(api)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + "invalid_token")
                .exchange()
                .expectStatus().isUnauthorized();
    }
}
