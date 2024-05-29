package com.demo.userlogin.springsecuritylogin.security.exceptions;

import com.demo.userlogin.springsecuritylogin.dto.ErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

// CustomAuthenticationEntryPoint handles authentication exceptions, such as invalid credentials.
@Component
@Slf4j
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException {
        String requestURI = request.getRequestURI();
        String method = request.getMethod();

        log.error("Unauthorized access attempt, method: '{}', URI: '{}'. Reason: {}",
                method, requestURI, authException.getMessage());

        ErrorResponse errorResponse = ErrorResponse.builder()
                .errorCode("UNAUTHORIZED")
                .errorMessage("Authentication failed. " + authException.getMessage())
                .build();
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json");
        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }
}
