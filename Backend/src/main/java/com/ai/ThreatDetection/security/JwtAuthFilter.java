package com.ai.ThreatDetection.security;


import java.io.IOException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.validation.constraints.NotNull;

/**
 * Runs once per request.
 * Responsibility:
 *  - Read Authorization header
 *  - If Bearer token present → validate via JwtUtil
 *  - Load user via UserDetailsService
 *  - Put Authentication in SecurityContext
 */
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;


    public JwtAuthFilter(JwtUtil jwtUtil, @Lazy UserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(
            @NotNull HttpServletRequest request,
            @NotNull HttpServletResponse response,
            @NotNull FilterChain filterChain
            ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        String username=null;
        String token=null;

        // Expecting: Authorization: Bearer <jwt>
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
            try {
                username = jwtUtil.extractUsername(token);
            } catch (Exception e) {
                // invalid token → leave username null; request will be unauthenticated
            }
        }


    // If we got a username and no one is authenticated yet…
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null)

    {
        // Load user from DB to verify + rebuild authorities
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        // Validate token matches this user and not expired
        if (jwtUtil.validateToken(token, userDetails)) {
            UsernamePasswordAuthenticationToken authToken =
                    new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities()
                    );
            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            // Put authentication into the SecurityContext → downstream knows who you are
            SecurityContextHolder.getContext().setAuthentication(authToken);
        }
    }

        // Continue the chain (either authenticated or anonymous)
        filterChain.doFilter(request, response);
    }
}
