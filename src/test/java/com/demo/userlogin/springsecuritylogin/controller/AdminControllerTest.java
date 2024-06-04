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
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collection;
import java.util.Collections;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AdminController.class)
@Import(TestSecurityConfig.class)
public class AdminControllerTest implements AutoCloseable {

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
    @WithMockUser(username = "adminuser", roles = {"ADMIN"})
    public void testSayHelloToAdmin_Success() throws Exception {
        UserPrincipal userPrincipal = createAdminUserPrincipal();

        mockMvc.perform(get("/api/v1/admin/hello")
                        .with(user(userPrincipal)))
                .andExpect(status().isOk())
                .andExpect(content().string("Heyyyyyyy, You are an Admin adminuser!"));
    }

    @Test
    @WithMockUser(username = "regularuser", roles = {"USER"})
    public void testSayHelloToAdmin_Forbidden() throws Exception {
        mockMvc.perform(get("/api/v1/admin/hello"))
                .andExpect(status().isForbidden());
    }

    private UserPrincipal createAdminUserPrincipal() {
        UserPrincipal userPrincipal = mock(UserPrincipal.class);
        when(userPrincipal.getUsername()).thenReturn("adminuser");
        when(userPrincipal.getAuthorities()).thenReturn(
                (Collection) Collections.singletonList(new SimpleGrantedAuthority("ROLE_ADMIN")));
        return userPrincipal;
    }

    @Override
    public void close() throws Exception {
        mocks.close();
    }
}
