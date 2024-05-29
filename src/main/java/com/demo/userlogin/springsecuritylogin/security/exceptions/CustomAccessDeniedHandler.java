package com.demo.userlogin.springsecuritylogin.security.exceptions;

import com.demo.userlogin.springsecuritylogin.dto.ErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

// CustomAccessDeniedHandler handles authorization exceptions, such as access denied.
@Component
@Slf4j
public class CustomAccessDeniedHandler implements AccessDeniedHandler {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
            AccessDeniedException accessDeniedException) throws IOException {
        String username = SecurityContextHolder.getContext().getAuthentication() != null
                ? SecurityContextHolder.getContext().getAuthentication().getName()
                : "anonymous";
        String requestURI = request.getRequestURI();
        String method = request.getMethod();

        log.error("Access denied for user '{}', method: '{}', URI: '{}'. Reason: {}",
                username, method, requestURI, accessDeniedException.getMessage());

        ErrorResponse errorResponse = ErrorResponse.builder()
                .errorCode("FORBIDDEN")
                .errorMessage(accessDeniedException.getMessage())
                .build();
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType("application/json");
        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }
}
