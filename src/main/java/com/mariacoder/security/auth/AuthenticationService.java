package com.mariacoder.security.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mariacoder.security.config.JwtService;
import com.mariacoder.security.config.SecurityConstants;
import com.mariacoder.security.domain.Role;
import com.mariacoder.security.domain.Token;
import com.mariacoder.security.domain.TokenType;
import com.mariacoder.security.domain.User;
import com.mariacoder.security.repository.TokenRepository;
import com.mariacoder.security.repository.UserRepository;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@RequiredArgsConstructor
@Service
public class AuthenticationService {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
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
        User userPersisted = userRepository.save(user);
        String jwtToken = jwtService.generateToken(userPersisted);
        String refreshToken = jwtService.generateRefreshToken(userPersisted);
        buildAndSaveToken(userPersisted, jwtToken);
        // TODO: what happen if we register n times
        // TODO: verify if user exists
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        // this line validate user and password ?
        manager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

        // this line is unnecessary? only to user in function to its username
        User userObtained = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("Credentials incorrect"));
        String jwtToken = jwtService.generateToken(userObtained);
        String refreshToken = jwtService.generateRefreshToken(userObtained);
        revokeAllUserTokens(userObtained);
        buildAndSaveToken(userObtained, jwtToken);

        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith(SecurityConstants.TOKEN_PREFIX)) {
            return;
        }

        String refreshToken = authHeader.substring(SecurityConstants.TOKEN_PREFIX.length());
        String username = jwtService.extractUsername(refreshToken);

        if (username != null) {
            User user = userRepository.findByUsername(username).orElseThrow();

            if (jwtService.isTokenValid(refreshToken, user)) {
                String accessToken = jwtService.generateRefreshToken(user);
                revokeAllUserTokens(user);
                buildAndSaveToken(user, accessToken);
                var authResponse = AuthenticationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build();
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
    }

    private void buildAndSaveToken(User userPersisted, String jwtToken) {
        Token token = Token.builder()
                .user(userPersisted)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .revoked(false)
                .expired(false)
                .build();

        tokenRepository.save(token);
    }

    private void revokeAllUserTokens(User user) {
        List<Token> validUserTokens = tokenRepository.findAllValidTokensByUser(user.getId());

        if (validUserTokens.isEmpty()) {
            return;
        }
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }
}
