package com.main.spring.security;

import com.main.spring.Entity.RefreshTokenRepository;
import com.main.spring.Entity.UserRepository;
import com.main.spring.security.auth.DetailService;
import com.main.spring.security.jwt.JwtAuthenticationFilter;
import com.main.spring.security.jwt.JwtAuthorizationFilter;
import com.main.spring.security.jwt.TokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;


@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    // loadUserByName() - username에 사용하는 사용자 존재시, 해당 사용자의 정보를 담은 UserDetails객체 리턴
    @Autowired
    private DetailService detailService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    RefreshTokenRepository refreshTokenRepository;

    @Autowired
    TokenProvider tokenProvider;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(detailService).passwordEncoder(bCryptPasswordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .httpBasic().disable()
                .formLogin().disable()
                .addFilter(new JwtAuthenticationFilter(authenticationManager(),refreshTokenRepository,tokenProvider))
                .addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository,refreshTokenRepository,tokenProvider))
                .authorizeRequests()//URL 별 권한 관리 설정 시작
                .antMatchers("/signup","/loginTest","/oauth/jwt/google","/token/refresh","/error").permitAll()
                .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .anyRequest().access("hasRole('ROLE_USER')");


    }
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }



}
