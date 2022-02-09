package com.main.spring.security.jwt;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.main.spring.Entity.RefreshToken;
import com.main.spring.Entity.RefreshTokenRepository;
import com.main.spring.security.auth.CustomUserDetails;
import com.main.spring.user.dto.LoginResponse;
import com.main.spring.user.dto.UserLoginDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;


//login 요청시 동작 필터
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    private final RefreshTokenRepository refreshTokenRepository;

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

            String accessToken = createAccessToken(customUserDetails);
            String refreshToken = null;

            // 리프레시토큰 디비에 리프레시 토큰이 없다면. ( 전에 수동으로 로그아웃 했거나 / 리프레시 토큰 만료 시 )
            if(!refreshTokenRepository.existsByUsername(customUserDetails.getUsername())) {
                // 새로운 리프레시 토큰 추가
                refreshToken = createRefreshToken(customUserDetails);
                log.info(" new Login! {}",refreshToken);

            }
            // 존재한다면. 있던거 반환
            else {
                RefreshToken findRefreshToken = refreshTokenRepository.findByUsername(customUserDetails.getUsername());
                refreshToken = findRefreshToken.getToken();
                log.info("Exists refreshToken {}", refreshToken);
            }
        Cookie refreshCookie = createCookie(refreshToken);
        ObjectMapper objectMapper = new ObjectMapper();
            response.addHeader(JwtProperties.ACCESS_TOKEN_HEADER_STRING,JwtProperties.TOKEN_PREFIX+accessToken);
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.addCookie(refreshCookie);
            log.info("SET COOKIE = {} ", refreshCookie);
            response.getWriter().write(objectMapper.writeValueAsString(new LoginResponse(JwtProperties.TOKEN_PREFIX+accessToken, "로그인 성공")));
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

    //JWT Access 토큰 생성
    public String createAccessToken(CustomUserDetails user){

        return JWT.create()
                .withSubject(user.getUsername())
                .withIssuer("springBack")
                .withIssuedAt(new Date())
                .withExpiresAt(JwtProperties.ACCESS_EXPIRY_DATE)
                .withClaim("username", user.getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));

    }
    //JWT Refresh 토큰 생성
    public String createRefreshToken(CustomUserDetails user){

        String refreshToken = JWT.create()
                .withIssuedAt(new Date())
                .withExpiresAt(JwtProperties.ACCESS_EXPIRY_DATE)
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));

        log.info("create! {}" , refreshToken);
        log.info("refreshTokenRepository : {}", refreshTokenRepository.getClass());
        if(refreshToken != null) {

            RefreshToken saveRefreshToken = refreshTokenRepository.save(new RefreshToken(user.getUsername(), refreshToken));
            return saveRefreshToken.getToken();
        }
        return null;
    }

    //refresh Token을 담을 쿠키 생성
    private Cookie createCookie(String refreshToken) {
        Cookie refreshCookie = new Cookie("token", refreshToken);
        refreshCookie.setSecure(true);
        refreshCookie.setHttpOnly(true);
        refreshCookie.setMaxAge(7*24*60*60); //7일
        refreshCookie.setPath("/");

        return refreshCookie;
    }
}
