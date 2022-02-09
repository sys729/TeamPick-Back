package com.main.spring.user.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.main.spring.Entity.RefreshToken;
import com.main.spring.Entity.RefreshTokenRepository;
import com.main.spring.Entity.User;
import com.main.spring.Entity.UserRepository;
import com.main.spring.security.jwt.JwtProperties;
import com.main.spring.user.dto.SignUpResponse;
import com.main.spring.user.dto.UserSignUpDTO;
import com.main.spring.user.service.UserService;
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

    //추후 수정 예정 (동작 확인을 위함)
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;


    @PostMapping("/signup")
    public ResponseEntity<?> userSignUp(@RequestBody UserSignUpDTO user){
        log.info("signup Controller = {}", user);
        try{
            userService.signUp(user);
            return ResponseEntity.ok().body(new SignUpResponse("회원가입 성공"));
        }catch (Exception e){
            return ResponseEntity.internalServerError().body(new SignUpResponse("회원가입 실패"));
        }

    }

    @PostMapping("/oauth/jwt/google")
    public String googleOauth (@RequestBody Map<String, Object> requestMap){
        return userService.oauthLogin(requestMap);
    }


    @GetMapping("/test")
    public String test1(){
        return "test1";
    }



    //TODO: 현재 Access Token 으로 서명하기 때문에, 액세스 토큰 만료 시, /token/refresh 동작 X
    // JwtAuthorizationFilter 에서 걸려버림. RefreshToken 으로 서명을 해야하는가
    /**
     * Headers 에 { authorization : expiredAccessToken ,
     *           refreshToken : refreshToken }
     *           추가 하여 테스트
     *
     */
    //액세스 토큰 만료 시, 재 발급 받는 url ( 만료된 Access Token과 만료되지 않은 Refresh Token이 헤더로 온다고 가정 )
    @GetMapping("/token/refresh")
    public String refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException{
        String header = request.getHeader(JwtProperties.ACCESS_TOKEN_HEADER_STRING);

        if (header != null){
            // Request에서 expire 된 access token을 가져온다.
            String expiredToken = request.getHeader(JwtProperties.ACCESS_TOKEN_HEADER_STRING).replace(JwtProperties.TOKEN_PREFIX, "");
            log.info("expiredToken = {}", expiredToken);

            // Request에서 refresh Token 확인
            String refreshToken = request.getHeader("refreshToken");
            log.info("refreshToken = {}", refreshToken);


            // 만료된 Access 토큰에서 Username 확인한다. X
            //TODO: 만료가 되었다면 TokenExpiredException 이 뜨게된다.
            // 다른 방법 찾아봐야한다.
            String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(expiredToken)
                    .getClaim("username").asString();
            log.info("username = {}", username);

            // 만료된 Access Token의 UserName으로 refreshToken이 위조되었는지 확인하기 위함
            RefreshToken findRefreshToken = refreshTokenRepository.findByUsername(username);
             // Header에서 넘어온 refreshToken과 DB에 저장된 refreshToken이 같다면 ( 위조되지 않앗다면 )
            if (refreshToken.equals(findRefreshToken.getToken()) && username != null ) {

                 //액세스 토큰 생성
                User user = userRepository.findByUsername(username);

                String newAccessToken = JWT.create()
                        .withSubject(user.getUsername())
                        .withIssuer("springBack")
                        .withIssuedAt(new Date())
                        .withExpiresAt(JwtProperties.ACCESS_EXPIRY_DATE)
                        .withClaim("username", user.getUsername())
                        .sign(Algorithm.HMAC512(JwtProperties.SECRET));
                return newAccessToken;
            }

        }
        return "error";
    }


}
