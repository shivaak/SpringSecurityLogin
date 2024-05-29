package com.demo.userlogin.springsecuritylogin.security;

import com.demo.userlogin.springsecuritylogin.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;

@Component
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    // Used by Spring Security to load user details when authenticating
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository
                .findByUsername(username)
                .map(user -> {
                    List<SimpleGrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority(user.getRole().name()));
                    return UserPrincipal.builder()
                            .username(user.getUsername())
                            .password(user.getPassword())
                            .authorities(authorities)
                            .accountNonExpired(user.isAccountNonExpired())
                            .accountNonLocked(user.isAccountNonLocked())
                            .credentialsNonExpired(user.isCredentialsNonExpired())
                            .enabled(user.isEnabled())
                            .build();
                })
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));
    }
}
