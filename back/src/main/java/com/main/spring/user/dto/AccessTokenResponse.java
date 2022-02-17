package com.main.spring.user.dto;

import lombok.AllArgsConstructor;
import lombok.Data;


@Data
@AllArgsConstructor
public class AccessTokenResponse {

    private String token;
    private String msg;
}
