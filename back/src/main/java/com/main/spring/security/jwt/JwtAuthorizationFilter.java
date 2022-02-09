package com.main.spring.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.main.spring.Entity.User;
import com.main.spring.Entity.UserRepository;
import com.main.spring.security.auth.CustomUserDetails;
import com.sun.xml.bind.v2.TODO;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 권한, 인증이 필요한 URL에서 필요한 JWT가 유효한지 판단하는 필터
 */
@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }



    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        log.info("AuthorizationFilter running");

        String header = request.getHeader(JwtProperties.ACCESS_TOKEN_HEADER_STRING);

        if(header == null || !header.startsWith(JwtProperties.TOKEN_PREFIX)){
            chain.doFilter(request,response);
            return;
        }

        //JWT 토큰 검증
        String token = request.getHeader(JwtProperties.ACCESS_TOKEN_HEADER_STRING).replace(JwtProperties.TOKEN_PREFIX, "");

        //TODO: 현재 Access Token 으로 서명하기 때문에, 액세스 토큰 만료 시, /token/refresh 동작 X
        // RefreshToken 으로 서명을 해야하는가

        // 서명 ( 유효한 토큰인지 확인 )
        String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(token)
                .getClaim("username").asString();

        // 서명이 정상이면
        if(username != null){
            User user = userRepository.findByUsername(username);

            CustomUserDetails userDetails = new CustomUserDetails(user);
            // Authentication 객체 생성
            Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());

            // 시큐리티 세션에 Authentication 객체 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        chain.doFilter(request,response);
    }
}
