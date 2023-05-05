package com.mariacoder.security.config;

import com.mariacoder.security.domain.Token;
import com.mariacoder.security.repository.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

import java.util.Optional;

import static com.mariacoder.security.config.SecurityConstants.HEADER_STRING;
import static com.mariacoder.security.config.SecurityConstants.TOKEN_PREFIX;

@RequiredArgsConstructor
@Service
public class LogoutService implements LogoutHandler {

    private final TokenRepository tokenRepository;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        // any client can log out
        String authHeader = request.getHeader(HEADER_STRING);

        if (authHeader == null || !authHeader.startsWith(TOKEN_PREFIX)) {
            return;
        }
        String jwt = authHeader.substring(TOKEN_PREFIX.length());
        Optional<Token> storedTokenOptional = tokenRepository.findByToken(jwt);

        if (storedTokenOptional.isPresent()) {
            Token storedToken = storedTokenOptional.get();
            storedToken.setRevoked(true);
            storedToken.setExpired(true);
            tokenRepository.save(storedToken);
        }
    }
}
