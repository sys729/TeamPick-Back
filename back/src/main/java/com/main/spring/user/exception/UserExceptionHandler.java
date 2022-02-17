package com.main.spring.user.exception;

import com.main.spring.user.controller.UserController;
import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@Slf4j
@RestControllerAdvice(assignableTypes = {UserController.class})
public class UserExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(value = { CustomException.class })
    protected ResponseEntity<UserErrorResponse> handleCustomException(CustomException e){
        log.info("handleCustomException  =  {}",e.getErrorType());
        return UserErrorResponse.toResponseEntity(e.getErrorType());
    }

}
