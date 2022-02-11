package com.main.spring.security.jwt;


import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;

import static com.main.spring.security.jwt.JwtProperties.REFRESH_EXPIRY_DATE;


@RequiredArgsConstructor
@Slf4j
@Service
public class TokenProvider {

    private final SecretKey secretKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(JwtProperties.SECRET));


    public String createAccessToken(String username) {

        /*
         { //header
           "alg":HS512"
         }.
         { // payload
           "username": username
           "iat":
           "exp":
         }.
         // SECRET KEY 로 서명한 부분
          asdkfjadljisdjfadl...
         */

        return Jwts.builder()
                .claim("username", username)
                .signWith(secretKey, SignatureAlgorithm.HS512)
                .setExpiration(JwtProperties.ACCESS_EXPIRY_DATE)
                .setIssuedAt(new Date())
                .compact();

    }
    public String createRefreshToken(){

        return Jwts.builder()
                .signWith(secretKey,SignatureAlgorithm.HS512)
                .setExpiration(REFRESH_EXPIRY_DATE)
                .setIssuedAt(new Date())
                .compact();
    }

    public boolean validateToken(String token){

        //parsClaimsJws 메서드가 Base 64로 디코딩 및 파싱
        // 헤더와 페이로드를 setSigningKey로 넘어온 시크릿을 이용해 서명 후, token의 서명과 비교

        try{
            Jwts.parserBuilder()
                    .setSigningKey(JwtProperties.SECRET)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            log.info("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            log.info("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            log.info("JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }

    public Claims getClaims(String token){
        //parsClaimsJws 메서드가 Base 64로 디코딩 및 파싱
        // 헤더와 페이로드를 setSigningKey로 넘어온 시크릿을 이용해 서명 후, token의 서명과 비교
        // 위조되지 않았다면 페이로드(Claims) 리턴
        // 만료되더라도 정보를 꺼낼 수 있음
        try {
            return Jwts
                    .parserBuilder()
                    .setSigningKey(JwtProperties.SECRET)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }

}
