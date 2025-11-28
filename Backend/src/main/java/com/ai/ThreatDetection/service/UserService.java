package com.ai.ThreatDetection.service;

import com.ai.ThreatDetection.entity.User;
import com.ai.ThreatDetection.exception.UserAlreadyExistsException;
import com.ai.ThreatDetection.repository.UserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.Optional;


/**
 * UserService:
 * - centralizes all user-related operations (create/find/list)
 * - hashes passwords using PasswordEncoder from SecurityConfig
 */
@Service
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    public final PasswordEncoder encoder;


    public UserService(UserRepository userRepository, PasswordEncoder encoder) {
        this.userRepository = userRepository;
        this.encoder = encoder;
    }

    public User registerUser(String email, String password, User.Role role){
        if (userRepository.findByEmail(email).isPresent()){
            throw new UserAlreadyExistsException("Email Already Registered");
        }
        User user = new User(email, encoder.encode(password), role);
        return userRepository.save(user);
    }


    public List<User> list(){
        return userRepository.findAll();
    }


    // ------------------------
    // FIND USER
    // ------------------------
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }



    // -------------------------------
    // MAIN FIX: LOGIN WILL WORK NOW
    // -------------------------------
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found: " + email));

        GrantedAuthority authority =
                new SimpleGrantedAuthority("ROLE_" + user.getRole().name());

        return new org.springframework.security.core.userdetails.User(
                user.getEmail(),
                user.getPassword(),
                Collections.singleton(authority)
        );
    }

    public void deleteUser(Long id) {
        userRepository.deleteById(id);
    }

    public void resetPassword(Long id, String newPassword) {
        User u = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));

        u.setPassword(encoder.encode(newPassword));
        userRepository.save(u);
    }

    public void updateRole(Long id, String role) {
        User u = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));

        u.setRole(User.Role.valueOf(role.toUpperCase()));
        userRepository.save(u);
    }

}
