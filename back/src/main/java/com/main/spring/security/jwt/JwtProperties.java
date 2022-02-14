package com.main.spring.security.jwt;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

public interface JwtProperties {

    String SECRET ="12421435643643765765AAAA32142154365435435643sdgfsdagadsvdsdasfsdarerwe4237543853753475465436";
    Date REFRESH_EXPIRY_DATE = Date.from(Instant.now().plus(1, ChronoUnit.MINUTES));
    Date ACCESS_EXPIRY_DATE = Date.from(Instant.now().plus(10, ChronoUnit.MINUTES));
    String TOKEN_PREFIX = "Bearer ";
    String ACCESS_TOKEN_HEADER_STRING = "Authorization";

}
