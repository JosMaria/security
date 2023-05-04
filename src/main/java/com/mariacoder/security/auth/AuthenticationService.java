package com.mariacoder.security.auth;

import com.mariacoder.security.domain.Role;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.mariacoder.security.config.JwtService;
import com.mariacoder.security.repository.UserRepository;
import com.mariacoder.security.domain.User;

import lombok.RequiredArgsConstructor;

@Slf4j
@RequiredArgsConstructor
@Service
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager manager;

    public AuthenticationResponse register(RegisterRequest request) {
        User user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        userRepository.save(user);

        return  generateAndResponseToken(user);
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        // this line validate user and password ?
        manager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

        // this line is unnecessary? only to user in function to its username
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("Credentials incorrect"));

        return generateAndResponseToken(user);
    }

    private AuthenticationResponse generateAndResponseToken(UserDetails userDetails) {
        String token = jwtService.generateToken(userDetails);
        return AuthenticationResponse.builder()
                .token(token)
                .build();
    }
}
