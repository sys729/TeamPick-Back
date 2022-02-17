package com.main.spring.user.controller;

import com.main.spring.security.jwt.TokenDTO;
import com.main.spring.user.dto.AccessTokenResponse;
import com.main.spring.user.dto.SignUpResponse;
import com.main.spring.user.dto.UserSignUpDTO;
import com.main.spring.user.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
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

    //권한 테스트용 추후 삭제 예정
    @GetMapping("/test")
    public String test1() {
        return "test1";
    }

    /**
     * Headers 에 { refreshToken : refreshToken 값 }
     * 추가 하여 테스트
     */
    //액세스 토큰 만료 시, 재 발급 받는 url ( Refresh Token이 헤더로 온다고 가정 )
    @GetMapping(value = {"/token/refresh","/autoLogin"})
    public ResponseEntity<?> reissueController(HttpServletRequest request) {
        TokenDTO tokenDTO = userService.reissue(request);

        Cookie refreshCookie = new Cookie("token", tokenDTO.getRefreshToken());
        refreshCookie.setSecure(true);
        refreshCookie.setHttpOnly(true);
        refreshCookie.setMaxAge(7*24*60*60); //7일
        refreshCookie.setPath("/");


        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                .body(new AccessTokenResponse(tokenDTO.getAccessToken(), "success"));
    }

}