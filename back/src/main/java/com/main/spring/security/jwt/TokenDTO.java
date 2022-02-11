package com.main.spring.security.jwt;


import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class TokenDTO {

    private String accessToken;
    private String refreshToken;

}
