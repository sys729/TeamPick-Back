package com.main.spring.user.service;


import com.main.spring.Entity.User;
import com.main.spring.Entity.UserRepository;
import com.main.spring.user.dto.UserSignUpDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

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

}
