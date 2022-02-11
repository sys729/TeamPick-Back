package com.main.spring.user.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.main.spring.Entity.RefreshToken;
import com.main.spring.Entity.RefreshTokenRepository;
import com.main.spring.Entity.User;
import com.main.spring.Entity.UserRepository;
import com.main.spring.security.jwt.JwtProperties;
import com.main.spring.security.jwt.TokenDTO;
import com.main.spring.security.jwt.TokenProvider;
import com.main.spring.user.dto.SignUpResponse;
import com.main.spring.user.dto.UserSignUpDTO;
import com.main.spring.user.service.UserService;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
@RestController
public class UserController {

    private final UserService userService;

    @PostMapping("/signup")
    public ResponseEntity<?> userSignUp(@RequestBody UserSignUpDTO user) {
        log.info("signup Controller = {}", user);
        try {
            userService.signUp(user);
            return ResponseEntity.ok().body(new SignUpResponse("회원가입 성공"));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(new SignUpResponse("회원가입 실패"));
        }

    }

    @PostMapping("/oauth/jwt/google")
    public String googleOauth(@RequestBody Map<String, Object> requestMap) {
        return userService.oauthLogin(requestMap);
    }


    @GetMapping("/test")
    public String test1() {
        return "test1";
    }



    /**
     * Headers 에 { authorization : expiredAccessToken ,
     * refreshToken : refreshToken }
     * 추가 하여 테스트
     */
    //액세스 토큰 만료 시, 재 발급 받는 url ( 만료된 Access Token과 만료되지 않은 Refresh Token이 헤더로 온다고 가정 )
    @GetMapping("/token/refresh")
    public String reissueController(HttpServletRequest request, HttpServletResponse response){
        TokenDTO tokenDTO = userService.reissue(request);

        response.addHeader("Authorization",tokenDTO.getAccessToken());
        response.addHeader("refreshToken", tokenDTO.getRefreshToken());

        return "success";
    }
}

