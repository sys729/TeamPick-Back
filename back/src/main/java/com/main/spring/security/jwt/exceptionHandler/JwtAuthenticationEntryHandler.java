package com.main.spring.security.jwt.exceptionHandler;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class JwtAuthenticationEntryHandler implements AuthenticationEntryPoint {

    // 유효한 자격증명을 제공하지 않고 접근하려 할때 401
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        log.info("Error Entry Handler!");

        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }
}
