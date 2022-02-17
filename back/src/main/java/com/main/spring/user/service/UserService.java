package com.main.spring.user.service;

import com.main.spring.Entity.User;
import com.main.spring.security.jwt.TokenDTO;
import com.main.spring.user.dto.UserSignUpDTO;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

public interface UserService {
    void signUp(UserSignUpDTO userSignUpDTO);
    String oauthLogin(Map<String, Object> data);
    TokenDTO reissue(HttpServletRequest request);
    void logout(String username);
//    TokenDTO autoLoginValidate(HttpServletRequest request);
}
