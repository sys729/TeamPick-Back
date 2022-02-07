package com.main.spring.security.jwt;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

public interface JwtProperties {

    String SECRET ="springBack";
    Date EXPIRY_DATE = Date.from(Instant.now().plus(1, ChronoUnit.DAYS));
    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";
}
