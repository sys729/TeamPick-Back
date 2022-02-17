package com.main.spring.user.exception;

import com.main.spring.security.jwt.exceptionHandler.ErrorType;
import lombok.Builder;
import lombok.Getter;
import org.springframework.http.ResponseEntity;

@Getter
@Builder
public class UserErrorResponse {

    private final int status;
    private final String error;
    private final String code;
    private final String message;

    public static ResponseEntity<UserErrorResponse> toResponseEntity(ErrorType errorType) {
        return ResponseEntity
                .status(errorType.getHttpStatus())
                .body(UserErrorResponse.builder()
                        .status(errorType.getHttpStatus().value())
                        .error(errorType.getHttpStatus().name())
                        .code(errorType.name())
                        .message(errorType.getMsg())
                        .build()
                );
    }
}

