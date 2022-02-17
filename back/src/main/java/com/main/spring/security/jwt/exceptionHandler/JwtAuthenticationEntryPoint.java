package com.main.spring.security.jwt.exceptionHandler;

import com.main.spring.security.jwt.TokenProvider;
import com.nimbusds.jose.shaded.json.JSONObject;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {


    // 유효한 자격증명을 제공하지 않고 접근하려 할때 401
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        log.info("Error Entry Handler!");

        String exception = (String) request.getAttribute("exception");
        log.info("Exception = {}",exception);
        ErrorType errorType;

        /**
         * 토큰이 없는 경우
         */
        if(exception == null){
            log.info("토큰이 없는 경우");
            errorType = ErrorType.UNAUTHORIZEDException;
            setResponse(response,errorType);
            return ;
        }

        /**
         * 토큰이 만료된 경우
         */

        if(exception.equals("ExpiredJwtException")){
            log.info("토큰이 만료된 경우");
            errorType = ErrorType.ExpiredJwtException;
            setResponse(response,errorType);
            return;
        }
        /**
         * 토큰 구조 에러 / 위조 된 경우
         */
        if(exception.equals("InvalidJwtException")){
            log.info("토큰 구조 에러 / 위조 된 경우");
            errorType = ErrorType.InvalidJwtException;
            setResponse(response,errorType);
            return;
        }

    }
    private void setResponse(HttpServletResponse response, ErrorType errorType) throws IOException{
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        JSONObject responseJson = new JSONObject();
        responseJson.put("message", errorType.getMsg());
        responseJson.put("status", errorType.getCode());

        response.getWriter().print(responseJson);
    }

}
