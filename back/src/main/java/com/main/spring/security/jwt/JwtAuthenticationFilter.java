package com.main.spring.security.jwt;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.main.spring.security.auth.CustomUserDetails;
import com.main.spring.user.dto.LoginResponse;
import com.main.spring.user.dto.UserLoginDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;


//login 요청시 동작 필터
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;


    // /login 시도를 위해 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.info("JwtAuthenticationFilter running");

        ObjectMapper om = new ObjectMapper();
        UserLoginDTO loginDTO = new UserLoginDTO();

        try{
            loginDTO = om.readValue(request.getInputStream(), UserLoginDTO.class);
        } catch (Exception e){
            log.info("Error LoginRequest : ",e);
        }

        log.info("JwtAuthenticationFilter {}", loginDTO);

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDTO.getUsername(),loginDTO.getPassword());

        Authentication authentication = authenticationManager.authenticate(authenticationToken);

        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();
        log.info("customUserDetails {}",customUserDetails.getUsername());


        return authentication;

    }

    //로그인 성공 시
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        CustomUserDetails customUserDetails = (CustomUserDetails) authResult.getPrincipal();

            String token = create(customUserDetails);
            ObjectMapper objectMapper = new ObjectMapper();
            response.addHeader(JwtProperties.HEADER_STRING,JwtProperties.TOKEN_PREFIX+token);
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write(objectMapper.writeValueAsString(new LoginResponse(JwtProperties.TOKEN_PREFIX+token,"로그인 성공")));

    }

    //로그인 실패 시
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        ObjectMapper objectMapper = new ObjectMapper();

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        response.getWriter().write(objectMapper.writeValueAsString(new LoginResponse(null,"로그인을 다시 시도해주세요")));
    }

    //JWT 토큰 생성
    public String create(CustomUserDetails user){

        return JWT.create()
                .withSubject(user.getUsername())
                .withIssuer("springBack")
                .withIssuedAt(new Date())
                .withExpiresAt(JwtProperties.EXPIRY_DATE)
                .withClaim("username", user.getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));

    }
}
