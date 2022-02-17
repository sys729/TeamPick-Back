package com.main.spring.user.exception;

import com.main.spring.security.jwt.exceptionHandler.ErrorType;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class CustomException extends RuntimeException {
    private final ErrorType errorType;
}