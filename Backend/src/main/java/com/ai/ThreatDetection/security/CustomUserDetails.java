package com.ai.ThreatDetection.security;


import com.ai.ThreatDetection.entity.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

/**
 * Bridges our User entity to Spring Security's UserDetails.
 * Maps role ADMIN/ANALYST to authorities ROLE_ADMIN/ROLE_ANALYST.
 */
public class CustomUserDetails implements UserDetails {

    private final User user;
    private final Collection<? extends GrantedAuthority> authorities;


    public CustomUserDetails(User user) {
        this.user = user;
        String roleName = "ROLE_" + user.getRole().name();
        this.authorities = Collections.singletonList(new SimpleGrantedAuthority(roleName));
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities()
    {
        return authorities;  // e.g., [ROLE_ADMIN]
    }

    @Override
    public String getPassword() {
        return user.getPassword(); // hashed
    }

    @Override
    public String getUsername() {
        return user.getEmail(); // we use email as principal
    }

    // Account flags (basic setup → all true)
    @Override public boolean isAccountNonExpired() { return true; }
    @Override public boolean isAccountNonLocked() { return true; }
    @Override public boolean isCredentialsNonExpired() { return true; }
    @Override public boolean isEnabled() { return true; }

    // Optional: expose entity if needed
    public User getUser() { return user; }


}
