package com.demo.userlogin.springsecuritylogin.security;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.demo.userlogin.springsecuritylogin.dto.ErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtDecoder jwtDecoder;
    private final JwtToUserPrincipalConverter jwtToUserPrincipalConverter;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String jwtToken = authHeader.substring(7);

        try {
            DecodedJWT decodedJWT = jwtDecoder.decode(jwtToken);
            UserPrincipal userPrincipal = jwtToUserPrincipalConverter.convert(decodedJWT);

            UserPrincipalAuthenticationToken authentication = new UserPrincipalAuthenticationToken(userPrincipal);
            SecurityContextHolder.getContext().setAuthentication(authentication);

            filterChain.doFilter(request, response);
        } catch (JWTVerificationException ex) {
            handleException(request, response, "Invalid or expired token", HttpStatus.UNAUTHORIZED, ex);
        } catch (Exception ex) {
            handleException(request, response, "An error occurred while processing the token", HttpStatus.INTERNAL_SERVER_ERROR, ex);
        } finally {
            // Clear the context after the filter chain execution to avoid any leakage of authentication info
            //SecurityContextHolder.clearContext();
        }
    }

    private void handleException(HttpServletRequest request, HttpServletResponse response, String message, HttpStatus status, Exception ex) throws IOException {
        String username = SecurityContextHolder.getContext().getAuthentication() != null
                ? SecurityContextHolder.getContext().getAuthentication().getName()
                : "anonymous";
        String requestURI = request.getRequestURI();
        String method = request.getMethod();

        log.error("Error processing JWT for user '{}', method: '{}', URI: '{}'. Reason: {}. Exception: {}",
                username, method, requestURI, message, ex.getMessage(), ex);

        ErrorResponse errorResponse = ErrorResponse.builder()
                .errorCode(status.getReasonPhrase())
                .errorMessage(message)
                .errors(Map.of())
                .build();
        response.setStatus(status.value());
        response.setContentType("application/json");
        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }
}
