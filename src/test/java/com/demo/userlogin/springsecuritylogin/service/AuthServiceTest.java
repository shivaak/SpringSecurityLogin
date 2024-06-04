package com.demo.userlogin.springsecuritylogin.service;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.demo.userlogin.springsecuritylogin.config.JwtProperties;
import com.demo.userlogin.springsecuritylogin.dto.LoginRequest;
import com.demo.userlogin.springsecuritylogin.dto.LoginResponse;
import com.demo.userlogin.springsecuritylogin.model.RefreshToken;
import com.demo.userlogin.springsecuritylogin.model.Role;
import com.demo.userlogin.springsecuritylogin.model.User;
import com.demo.userlogin.springsecuritylogin.repository.RefreshTokenRepository;
import com.demo.userlogin.springsecuritylogin.repository.UserRepository;
import com.demo.userlogin.springsecuritylogin.security.JwtDecoder;
import com.demo.userlogin.springsecuritylogin.security.JwtIssuer;
import com.demo.userlogin.springsecuritylogin.security.JwtToUserPrincipalConverter;
import com.demo.userlogin.springsecuritylogin.security.UserPrincipal;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class AuthServiceTest {

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private JwtIssuer jwtIssuer;

    @Mock
    private JwtDecoder jwtDecoder;

    @Mock
    private JwtToUserPrincipalConverter jwtToUserPrincipalConverter;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private UserRepository userRepository;

    @Mock
    private JwtProperties jwtProperties;

    @InjectMocks
    private AuthService authService;

    private Cache<String, Boolean> accessTokenBlacklistCache;
    private Cache<String, Boolean> refreshTokenBlacklistCache;
    private User user;
    private UserPrincipal userPrincipal;
    private DecodedJWT decodedJWT;

    @BeforeEach
    public void setUp() {
        accessTokenBlacklistCache = Caffeine.newBuilder()
                .expireAfterWrite(60, TimeUnit.MINUTES)
                .build();
        refreshTokenBlacklistCache = Caffeine.newBuilder()
                .expireAfterWrite(60, TimeUnit.MINUTES)
                .build();

        authService = new AuthService(authenticationManager, jwtIssuer, jwtDecoder, jwtToUserPrincipalConverter,
                refreshTokenRepository, userRepository, jwtProperties, accessTokenBlacklistCache, refreshTokenBlacklistCache);

        user = User.builder()
                .username("testuser")
                .password("password")
                .role(Role.ROLE_USER)
                .firstName("Test")
                .lastName("User")
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .build();

        userPrincipal = UserPrincipal.create(user);

        decodedJWT = mock(DecodedJWT.class);
    }

    @Test
    public void testLogin_Success() {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername("testuser");
        loginRequest.setPassword("password");

        Authentication authentication = new UsernamePasswordAuthenticationToken(userPrincipal, "password", userPrincipal.getAuthorities());

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class))).thenReturn(authentication);
        when(jwtIssuer.issueToken(any(UserPrincipal.class))).thenReturn("access-token");
        when(jwtIssuer.issueRefreshToken(any(UserPrincipal.class))).thenReturn("refresh-token");
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(new RefreshToken());

        LoginResponse loginResponse = authService.login(loginRequest);

        assertThat(loginResponse.getToken()).isEqualTo("access-token");
        assertThat(loginResponse.getRefreshToken()).isEqualTo("refresh-token");
        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(jwtIssuer).issueToken(any(UserPrincipal.class));
        verify(jwtIssuer).issueRefreshToken(any(UserPrincipal.class));
        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }

    @Test
    public void testRefresh_Success() {
        when(jwtDecoder.decode("refresh-token")).thenReturn(decodedJWT);
        when(decodedJWT.getClaim("type")).thenReturn(mock(Claim.class));
        when(decodedJWT.getClaim("type").asString()).thenReturn("refresh");
        when(jwtToUserPrincipalConverter.convert(any(DecodedJWT.class))).thenReturn(userPrincipal);
        when(jwtIssuer.issueToken(any(UserPrincipal.class))).thenReturn("new-access-token");
        when(jwtIssuer.issueRefreshToken(any(UserPrincipal.class))).thenReturn("new-refresh-token");
        when(refreshTokenRepository.findByToken("refresh-token")).thenReturn(Optional.of(new RefreshToken(1L, "refresh-token", user, Instant.now().plusSeconds(3600))));
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));

        LoginResponse loginResponse = authService.refresh("refresh-token");

        assertThat(loginResponse.getToken()).isEqualTo("new-access-token");
        assertThat(loginResponse.getRefreshToken()).isEqualTo("new-refresh-token");
        verify(jwtDecoder).decode("refresh-token");
        verify(jwtToUserPrincipalConverter).convert(any(DecodedJWT.class));
        verify(jwtIssuer).issueToken(any(UserPrincipal.class));
        verify(jwtIssuer).issueRefreshToken(any(UserPrincipal.class));
        verify(refreshTokenRepository).deleteByToken("refresh-token");
        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }

    @Test
    public void testLogout_Success() {
        when(jwtDecoder.decode("access-token")).thenReturn(decodedJWT);
        when(jwtDecoder.decode("refresh-token")).thenReturn(decodedJWT);
        when(decodedJWT.getClaim("type")).thenReturn(mock(Claim.class));
        when(decodedJWT.getClaim("type").asString()).thenReturn("access").thenReturn("refresh");
        when(decodedJWT.getSubject()).thenReturn("testuser");

        authService.logout("access-token", "refresh-token");

        verify(jwtDecoder, times(2)).decode(anyString());
        verify(refreshTokenRepository).deleteByToken("refresh-token");
        assertThat(accessTokenBlacklistCache.getIfPresent("access-token")).isTrue();
        assertThat(refreshTokenBlacklistCache.getIfPresent("refresh-token")).isTrue();
    }

    @Test
    public void testRefresh_InvalidTokenType() {
        when(jwtDecoder.decode("invalid-refresh-token")).thenReturn(decodedJWT);
        when(decodedJWT.getClaim("type")).thenReturn(mock(Claim.class));
        when(decodedJWT.getClaim("type").asString()).thenReturn("access");

        assertThrows(JWTVerificationException.class, () -> authService.refresh("invalid-refresh-token"));
    }

    @Test
    public void testLogout_InvalidAccessTokenType() {
        when(jwtDecoder.decode("access-token")).thenReturn(decodedJWT);
        when(decodedJWT.getClaim("type")).thenReturn(mock(Claim.class));
        when(decodedJWT.getClaim("type").asString()).thenReturn("refresh");

        assertThrows(JWTVerificationException.class, () -> authService.logout("access-token", "refresh-token"));
    }

    @Test
    public void testLogout_InvalidRefreshTokenType() {
        when(jwtDecoder.decode("access-token")).thenReturn(decodedJWT);
        when(jwtDecoder.decode("refresh-token")).thenReturn(decodedJWT);
        when(decodedJWT.getClaim("type")).thenReturn(mock(Claim.class));
        when(decodedJWT.getClaim("type").asString()).thenReturn("access").thenReturn("access");

        assertThrows(JWTVerificationException.class, () -> authService.logout("access-token", "refresh-token"));
    }

    @Test
    public void testLogout_TokensDoNotMatch() {
        DecodedJWT decodedAccessToken = mock(DecodedJWT.class);
        DecodedJWT decodedRefreshToken = mock(DecodedJWT.class);

        when(jwtDecoder.decode("access-token")).thenReturn(decodedAccessToken);
        when(jwtDecoder.decode("refresh-token")).thenReturn(decodedRefreshToken);
        when(decodedAccessToken.getClaim("type")).thenReturn(mock(Claim.class));
        when(decodedRefreshToken.getClaim("type")).thenReturn(mock(Claim.class));
        when(decodedAccessToken.getClaim("type").asString()).thenReturn("access");
        when(decodedRefreshToken.getClaim("type").asString()).thenReturn("refresh");
        when(decodedAccessToken.getSubject()).thenReturn("user1");
        when(decodedRefreshToken.getSubject()).thenReturn("user2");

        assertThrows(JWTVerificationException.class, () -> authService.logout("access-token", "refresh-token"));
    }
}
