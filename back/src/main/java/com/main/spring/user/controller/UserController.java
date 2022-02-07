package com.main.spring.user.controller;

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

@Slf4j
@RequiredArgsConstructor
@RestController
public class UserController {

    private final UserService userService;



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
    @GetMapping("/test")
    public String test1(){
        return "test1";
    }


}
