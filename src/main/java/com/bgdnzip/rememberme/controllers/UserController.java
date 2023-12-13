package com.bgdnzip.rememberme.controllers;

import com.bgdnzip.rememberme.models.requests.CreateUserRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class UserController {
    @Autowired
    JdbcUserDetailsManager jdbcUserDetailsManager;
    @Autowired
    PasswordEncoder passwordEncoder;

    @PostMapping("/user/create")
    public ResponseEntity<?> createUser(@RequestBody CreateUserRequest request) {
        if (!createRequestValid(request)) {
            return ResponseEntity.badRequest().build();
        }
        UserDetails userDetails = User.builder()
                .username(request.username())
                .password(passwordEncoder.encode(request.password1()))
                .authorities("USER")
                .build();
        jdbcUserDetailsManager.createUser(userDetails);
        return ResponseEntity.ok(userDetails);
    }


    @GetMapping("/user")
    public ResponseEntity<?> user(@AuthenticationPrincipal UserDetails user) {
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        return ResponseEntity.ok(user);
    }

    private boolean createRequestValid(CreateUserRequest request) {
        if (request == null) return false;
        if (request.username() == null || request.username().length() <= 4) return false;
        if (request.password1() == null || !request.password1().equals(request.password2())) return false;
        return true;
    }
}
