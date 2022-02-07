package com.main.spring.user.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@AllArgsConstructor
public class UserLoginDTO {

    private String username;
    private String password;


    public UserLoginDTO() {

    }
}
