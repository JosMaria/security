package com.mariacoder.security.auth;

import com.mariacoder.security.config.JwtService;
import com.mariacoder.security.domain.Role;
import com.mariacoder.security.domain.Token;
import com.mariacoder.security.domain.TokenType;
import com.mariacoder.security.domain.User;
import com.mariacoder.security.repository.TokenRepository;
import com.mariacoder.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Slf4j
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
        buildAndSaveToken(userPersisted, jwtToken);
        // TODO: what happen if we register n times
        // TODO: verify if user exists
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    private void buildAndSaveToken(User userPersisted, String jwtToken) {
        Token token  = Token.builder()
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

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        // this line validate user and password ?
        manager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

        // this line is unnecessary? only to user in function to its username
        User userObtained = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("Credentials incorrect"));
        String jwtToken = jwtService.generateToken(userObtained);
        revokeAllUserTokens(userObtained);
        buildAndSaveToken(userObtained, jwtToken);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}
