package com.demo.userlogin.springsecuritylogin.security.exceptions;

import com.demo.userlogin.springsecuritylogin.dto.ErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExecutionChain;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.io.IOException;

@Component
@Slf4j
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    private RequestMappingHandlerMapping requestMappingHandlerMapping;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException {
        try {
            HandlerExecutionChain handler = requestMappingHandlerMapping.getHandler(request);
            if(handler == null) {
                throw new Exception("Resource not found");
            }
            // If no exception is thrown, the URL is valid and it is an authentication issue
            log.error("Unauthorized access attempt, method: '{}', URI: '{}'. Reason: {}",
                    request.getMethod(), request.getRequestURI(), authException.getMessage(), authException);

            ErrorResponse errorResponse = ErrorResponse.builder()
                    .errorCode("UNAUTHORIZED")
                    .errorMessage("Authentication failed. " + authException.getMessage())
                    .build();
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType("application/json");
            response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
        } catch (Exception e) {
            // If Exception is thrown, the URL is invalid
            log.error("Resource not found, method: '{}', URI: '{}'.", request.getMethod(), request.getRequestURI(), e);

            ErrorResponse errorResponse = ErrorResponse.builder()
                    .errorCode("NOT_FOUND")
                    .errorMessage("The requested resource was not found.")
                    .build();
            response.setStatus(HttpStatus.NOT_FOUND.value());
            response.setContentType("application/json");
            response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
        }
    }
}
