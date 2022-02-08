package com.main.spring.user.service;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.main.spring.Entity.User;
import com.main.spring.Entity.UserRepository;
import com.main.spring.oauth.GoogleUser;
import com.main.spring.oauth.OauthUserInfo;
import com.main.spring.security.jwt.JwtProperties;
import com.main.spring.user.dto.UserSignUpDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Map;
import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
@Service
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;



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
                .withExpiresAt(JwtProperties.EXPIRY_DATE)
                .withClaim("username", userResult.getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));

    }

}
