package com.main.spring.user.dto;

import lombok.Data;

@Data
public class UserSignUpDTO {
    private String username;
    private String password;
    private String email;
    private String name;
    private int age;



}
