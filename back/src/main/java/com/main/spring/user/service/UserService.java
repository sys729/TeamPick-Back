package com.main.spring.user.service;

import com.main.spring.Entity.User;
import com.main.spring.user.dto.UserSignUpDTO;
import org.springframework.security.crypto.password.PasswordEncoder;

public interface UserService {
    void signUp(UserSignUpDTO userSignUpDTO);
}
