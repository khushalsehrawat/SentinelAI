package com.ai.ThreatDetection.controller;


import com.ai.ThreatDetection.dto.LoginRequest;
import com.ai.ThreatDetection.dto.RegisterRequest;
import com.ai.ThreatDetection.entity.User;
import com.ai.ThreatDetection.security.JwtUtil;
import com.ai.ThreatDetection.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Authentication endpoints (public):
 * - POST /api/auth/register
 * - POST /api/auth/login
 *
 * After successful login → returns JWT token to use in Authorization header.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;


    public AuthController(UserService userService, AuthenticationManager authenticationManager, JwtUtil jwtUtil) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest req){
        User created = userService.registerUser(req.getEmail(), req.getPassword(), req.getRole());
        return ResponseEntity.ok("Registered: " + created.getEmail()+" as " + created.getRole());
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest req)
    {
        // Verify credentials via AuthenticationManager
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.getEmail(), req.getPassword())
        );
        // Build token from authenticated principal
        UserDetails userDetails = (UserDetails) auth.getPrincipal();
        String token = jwtUtil.generateToken(userDetails);
        return ResponseEntity.ok(
                Map.of(
                        "token", token,
                        "email", userDetails.getUsername(),
                        "roles", userDetails.getAuthorities()
                )
        );
    }


}
