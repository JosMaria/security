package com.mariacoder.security.config;

import org.springframework.beans.factory.annotation.Value;

public class SecurityConstants {

    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String HEADER_STRING = "Authorization";

    @Value("${application.security.jwt.secret-key}")
    public static String SECRET_KEY;

    @Value("${application.security.jwt.expiration}")
    public static long JWT_EXPIRATION;

    @Value("${application.security.jwt.refresh-token.expiration}")
    public static long REFRESH_JWT_EXPIRATION;

    public static final long ONE_SECOND = 1000;
    public static final long ONE_MINUTE = ONE_SECOND * 60;
    public static final long ONE_HOUR = ONE_MINUTE * 60;
}
