package com.main.spring.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.main.spring.Entity.RefreshToken;
import com.main.spring.Entity.RefreshTokenRepository;
import com.main.spring.Entity.User;
import com.main.spring.Entity.UserRepository;
import com.main.spring.security.auth.CustomUserDetails;
import com.sun.xml.bind.v2.TODO;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

/**
 * 권한, 인증이 필요한 URL에서 필요한 JWT가 유효한지 판단하는 필터
 */
@Slf4j
//@RequiredArgsConstructor
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private final UserRepository userRepository;
    private final TokenProvider tokenProvider;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository,TokenProvider tokenProvider) {
        super(authenticationManager);
        this.userRepository = userRepository;
        this.tokenProvider = tokenProvider;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        log.info("AuthorizationFilter running");


            String header = request.getHeader(JwtProperties.ACCESS_TOKEN_HEADER_STRING);

            if (header == null || !header.startsWith(JwtProperties.TOKEN_PREFIX)) {
                chain.doFilter(request, response);
                return;
            }

            //JWT 토큰 검증

            //header 에서 access token 꺼냄
            String token = resolveToken(request);
            log.info("Token = {}", token);


            // 서명 ( 유효한 토큰인지 확인 ) 위조시 예외처리 된다.
            if(StringUtils.hasText(token) && tokenProvider.validateToken(token,request)){
                String username = tokenProvider.getClaims(token).get("username").toString();
                User user = userRepository.findByUsername(username);
                CustomUserDetails userDetails = new CustomUserDetails(user);
                // Authentication 객체 생성
                Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                // 시큐리티 세션에 Authentication 객체 저장
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

        chain.doFilter(request, response);
    }


    private String resolveToken(HttpServletRequest request){
        String bearerToken = request.getHeader(JwtProperties.ACCESS_TOKEN_HEADER_STRING);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

}


