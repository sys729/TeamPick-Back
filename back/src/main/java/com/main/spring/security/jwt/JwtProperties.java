package com.main.spring.security.jwt;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

public interface JwtProperties {

    String SECRET ="springBack";
    Date REFRESH_EXPIRY_DATE = Date.from(Instant.now().plus(7, ChronoUnit.DAYS));
    Date ACCESS_EXPIRY_DATE = Date.from(Instant.now().plus(10, ChronoUnit.MINUTES));
    String TOKEN_PREFIX = "Bearer ";
    String ACCESS_TOKEN_HEADER_STRING = "Authorization";

}
