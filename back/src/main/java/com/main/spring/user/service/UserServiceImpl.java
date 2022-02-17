package com.main.spring.user.service;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.main.spring.Entity.RefreshToken;
import com.main.spring.Entity.RefreshTokenRepository;
import com.main.spring.Entity.User;
import com.main.spring.Entity.UserRepository;
import com.main.spring.oauth.GoogleUser;
import com.main.spring.oauth.OauthUserInfo;
import com.main.spring.security.jwt.JwtProperties;
import com.main.spring.security.jwt.TokenDTO;
import com.main.spring.security.jwt.TokenProvider;
import com.main.spring.security.jwt.exceptionHandler.ErrorType;
import com.main.spring.user.dto.UserSignUpDTO;
import com.main.spring.user.exception.CustomException;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
@Service
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final TokenProvider tokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;



    public void signUp(UserSignUpDTO userSignUpDTO){
        log.info("signup service = {}", userSignUpDTO);

        if(userSignUpDTO == null){
            throw new RuntimeException("Invalid arguments");
        }
        //해당 유저 아이디가 이미 존재하면
        if(userRepository.existsByUsername(userSignUpDTO.getUsername())){
            throw new RuntimeException("User already exists");
        }
        User user = User.builder()
                .username(userSignUpDTO.getUsername())
                .email(userSignUpDTO.getEmail())
                .password(bCryptPasswordEncoder.encode(userSignUpDTO.getPassword()))
                .name(userSignUpDTO.getName())
                .age(userSignUpDTO.getAge())
                .role("ROLE_USER")
                .build();
        userRepository.save(user);
    }

    public String oauthLogin(Map<String, Object> data){
        log.info("oauth Login running = {} ", data);
        OauthUserInfo oauthUser=
                new GoogleUser((Map<String, Object>) data.get("profileObj"));

        User userResult = userRepository.findByUsername(oauthUser.getProvider()+"_"+oauthUser.getProviderId());

        // 회원가입을 안했던 유저라면
        if(userResult == null) {
            String uuid = UUID.randomUUID().toString();
            User userRequest = User.builder()
                    .username(oauthUser.getProvider()+"_"+oauthUser.getProviderId())
                    .password(bCryptPasswordEncoder.encode(uuid))
                    .name(oauthUser.getName())
                    .email(oauthUser.getEmail())
                    .provider(oauthUser.getProvider())
                    .providerId(oauthUser.getProviderId())
                    .role("ROLE_USER")
                    .age(0)
                    .build();
            userResult = userRepository.save(userRequest);
        }


        return JWT.create()
                .withSubject(userResult.getUsername())
                .withIssuer("springBack")
                .withIssuedAt(new Date())
                .withExpiresAt(JwtProperties.REFRESH_EXPIRY_DATE)
                .withClaim("username", userResult.getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));

    }

    public void logout(String username){
        refreshTokenRepository.deleteTokenByUsername(username);
    }

    /**
     *  토큰 재발급 및 자동 로그인 가능 여부
     * @param request
     * @return TokenDTO(newAccessToken,newRefreshToken)
     *
     * @Exception ExpiredJwtException 401
     * @Exception NULL_REFRESH_TOKEN 400
     * @Exception UNAUTHORIZEDException 401
     * @Exception MISMATCH_REFRESH_TOKEN 401
     */
    public TokenDTO reissue(HttpServletRequest request){

        String refreshToken = request.getHeader("refreshToken");

        if(refreshToken == null){
            throw new CustomException(ErrorType.NULL_REFRESH_TOKEN);
        }
        log.info("In header refreshToken {}",refreshToken);

        if(!tokenProvider.validateToken(refreshToken,request)){
            throw new CustomException(ErrorType.ExpiredJwtException);
        }

        String username = tokenProvider.getClaims(refreshToken).get("username").toString();
        log.info("username = {}", username);

        // 저장소에서 username 을 기반으로 Refresh Token값을 가져온다.
        RefreshToken findRefreshToken = refreshTokenRepository.findByUsername(username);
        if(findRefreshToken == null){
            throw new CustomException(ErrorType.UNAUTHORIZEDException);
        }

        log.info("findRefreshToken = {}",findRefreshToken.getToken());
        log.info("refreshToken is equal? = {}", findRefreshToken.getToken().equals(refreshToken));

        // Refresh Token이 일치하는지 검사한다.
        if(!findRefreshToken.getToken().equals(refreshToken)){
            throw new CustomException(ErrorType.MISMATCH_REFRESH_TOKEN);
        }

        // 새로운 토큰을 생성한다.
        String newAccessToken = tokenProvider.createAccessToken(username);
        String newRefreshToken = tokenProvider.createRefreshToken(username);

        // 새로운 Refresh Token을 저장소에 업데이트 한다.
        RefreshToken newRT = findRefreshToken.updateToken(newRefreshToken);
        refreshTokenRepository.save(newRT);

        return new TokenDTO(newAccessToken,newRefreshToken);

    }

}
