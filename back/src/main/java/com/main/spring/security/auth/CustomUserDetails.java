package com.main.spring.security.auth;

import com.main.spring.Entity.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

//UserDetails - 사용자의 정보를 담는 인터페이스 구현
// 로그인 진행이 완료되면 시큐리티 Session 만듬 (Security ContextHolder)
// Security Session => Authentication => UserDetails
public class CustomUserDetails implements UserDetails {

    private User user; //Composition

    public CustomUserDetails(User user) {
        this.user = user;
    }

    // 해당 User의 ROLE을 리턴
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> auth = new ArrayList<>();
        auth.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return auth;

    }

    //User의 패스워드 리턴
    @Override
    public String getPassword() {
        return user.getPassword();
    }

    //User의 Name 리턴
    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}

