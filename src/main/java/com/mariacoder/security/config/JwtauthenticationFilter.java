package com.mariacoder.security.config;

import java.io.IOException;

import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Component
public class JwtauthenticationFilter extends OncePerRequestFilter {

    private static final String PREFIX_TOKEN = "Bearer ";
    private static final String AUTHORIZATION = "Authorization";

    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader(AUTHORIZATION);
        
        if (authHeader == null || !authHeader.startsWith(PREFIX_TOKEN)) {
            filterChain.doFilter(request, response);
            return;
        }

        String jwt = authHeader.substring(PREFIX_TOKEN.length());
        String username = jwtService.extractUserName(jwt);
    }

}
