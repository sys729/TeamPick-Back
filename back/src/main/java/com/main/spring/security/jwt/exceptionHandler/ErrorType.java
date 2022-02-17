package com.main.spring.security.jwt.exceptionHandler;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum ErrorType {
    NULL_REFRESH_TOKEN(400,"리프레시 토큰이 존재하지 않습니다.",HttpStatus.BAD_REQUEST),
    INVALID_REFRESH_TOKEN(400, "리프레시 토큰이 유효하지 않습니다",HttpStatus.BAD_REQUEST),
    MISMATCH_REFRESH_TOKEN(400, "리프레시 토큰의 유저 정보가 일치하지 않습니다",HttpStatus.BAD_REQUEST),
    UsernameOrPasswordNotFoundException (400, "아이디 또는 비밀번호가 일치하지 않습니다.", HttpStatus.BAD_REQUEST),

    UNAUTHORIZEDException (401, "로그인 후 이용가능합니다.", HttpStatus.UNAUTHORIZED),
    ExpiredJwtException(401, "기존 토큰이 만료되었습니다.",HttpStatus.UNAUTHORIZED),
    InvalidJwtException(401, "위조된 토큰입니다.",HttpStatus.UNAUTHORIZED),

    ForbiddenException (403, "해당 요청에 대한 권한이 없습니다.", HttpStatus.FORBIDDEN),
    ReLogin(401, "리프레시 토큰이 만료되었습니다. 다시 로그인 해주세요",HttpStatus.UNAUTHORIZED),;


    private int code;

    private String msg;

    private HttpStatus httpStatus;


    ErrorType(int code, String msg, HttpStatus httpStatus) {
        this.code = code;
        this.msg = msg;
        this.httpStatus = httpStatus;
    }
}
