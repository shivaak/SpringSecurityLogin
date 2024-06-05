package com.demo.userlogin.springsecuritylogin.controller;

import com.demo.userlogin.springsecuritylogin.config.TestSecurityConfig;
import com.demo.userlogin.springsecuritylogin.security.UserPrincipal;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collection;
import java.util.Collections;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(HelloController.class)
@Import(TestSecurityConfig.class)
@ActiveProfiles("test")
public class HelloControllerTest implements AutoCloseable {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private AutoCloseable mocks;

    @BeforeEach
    public void setUp() {
        mocks = MockitoAnnotations.openMocks(this);
    }

    @Test
    @WithMockUser(username = "testuser", roles = {"USER"})
    public void testSayHello_Success() throws Exception {
        UserPrincipal userPrincipal = createUserPrincipal();

        mockMvc.perform(get("/api/v1/hello")
                        .with(user(userPrincipal)))
                .andExpect(status().isOk())
                .andExpect(content().string("Hello, testuser!"));
    }

    @Test
    public void testSayHello_Forbidden() throws Exception {
        mockMvc.perform(get("/api/v1/hello"))
                .andExpect(status().isForbidden());
    }

    private UserPrincipal createUserPrincipal() {
        UserPrincipal userPrincipal = mock(UserPrincipal.class);
        when(userPrincipal.getUsername()).thenReturn("testuser");
        when(userPrincipal.getAuthorities()).thenReturn(
                (Collection) Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        return userPrincipal;
    }

    @Override
    public void close() throws Exception {
        mocks.close();
    }
}
